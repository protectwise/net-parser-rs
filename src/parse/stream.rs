use crate::{
    errors::Error,
    parse::{
        global_header::GlobalHeader,
        record::PcapRecord
    }
};

use futures::{self, io::AsyncRead, io::AsyncReadExt, Poll, stream::Stream};
use log::*;
use std::{
    self,
    convert::{From, TryInto},
    pin::Pin
};

pub struct RecordStream<S> {
    inner: S,
    endianness: Option<nom::Endianness>,
    buffer: Vec<u8>,
    outstanding: Vec<u8>
}

impl<S> RecordStream<S> {
    pub fn new(
        inner: S,
        endianness: Option<nom::Endianness>,
        capacity: usize
    ) -> RecordStream<S> {
        RecordStream {
            inner: inner,
            endianness: endianness,
            buffer:  Vec::with_capacity(capacity),
            outstanding: vec![]
        }
    }
}

impl<S> From<S> for RecordStream<S> where S: AsyncRead {
    fn from(v: S) -> Self {
        RecordStream::new(v, None, 10_000_000)
    }
}

impl<S> Stream for RecordStream<S>
    where S: AsyncRead + Unpin {

    type Item=Vec<PcapRecord>;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, lw: &std::task::LocalWaker) -> futures::Poll<Option<Self::Item>> {
        let this = &mut *self;

        this.buffer.resize(this.buffer.capacity(), 0u8);

        match Pin::new(&mut this.inner).poll_read(lw, &mut this.buffer) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => {
                error!("Failed to read: {:?}", e);
                Poll::Ready(None)
            },
            Poll::Ready(Ok(bytes_read)) => {
                debug!("Read {} bytes", bytes_read);
                if bytes_read == 0 {
                    return Poll::Ready(None);
                }

                this.outstanding.extend(this.buffer.drain(0..bytes_read));

                let (rem, records) = match this.endianness {
                    None => {
                        //parse global header
                        match crate::CaptureParser::parse_file(&this.outstanding) {
                            Err(e) => {
                                error!("Failed to parse: {:?}", e);
                                return Poll::Ready(None);
                            }
                            Ok((rem, (gh, records))) => {
                                this.endianness = Some(gh.endianness());
                                (rem, records)
                            }
                        }
                    }
                    Some(ref e) => {
                        //parse records
                        match crate::CaptureParser::parse_records(&this.outstanding, e.clone()) {
                            Err(e) => {
                                error!("Failed to parse: {:?}", e);
                                return Poll::Ready(None);
                            }
                            Ok(t) => {
                                t
                            }
                        }
                    }
                };

                let unread_position = this.outstanding.len() - rem.len();
                this.outstanding = this.outstanding.drain(unread_position..).collect();

                Poll::Ready(Some(records))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate test;

    use super::*;

    use crate::{parse::record::PcapRecord, CaptureParser};

    use self::test::Bencher;
    use futures::{
        StreamExt
    };
    use nom::Endianness;
    use std::{io::Read, path::PathBuf};

    struct FileWrapper {
        inner: std::fs::File
    }

    impl AsyncRead for FileWrapper {
        fn poll_read(&mut self, lw: &std::task::LocalWaker, buf: &mut [u8])
                     -> Poll<std::io::Result<usize>> {
            Poll::Ready(self.inner.read(buf))
        }
    }

    #[test]
    fn create_records_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        let bytes_stream = std::fs::File::open(pcap_path.clone())
            .expect(&format!("Failed to open pcap path {:?}", pcap_path));

        let fut_records = async {
            let reader: RecordStream<_> = FileWrapper { inner: bytes_stream }.into();
            let r: Vec<_> = await!(
                reader.collect()
            );
            r
        };

        let vec_of_records = futures::executor::block_on(fut_records);
        let records: Vec<_> = vec_of_records.iter().flatten().collect();

        assert_eq!(records.len(), 246137);
    }

    #[bench]
    fn bench_create_stream_from_file(b: &mut Bencher) {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        b.iter(|| {
            let bytes_stream = std::fs::File::open(pcap_path.clone())
                .expect(&format!("Failed to open pcap path {:?}", pcap_path));

            let fut_records = async {
                let reader: RecordStream<_> = FileWrapper { inner: bytes_stream }.into();
                let r: Vec<_> = await!(reader
                    .collect()
                );
                r
            };

            let vec_of_records = futures::executor::block_on(fut_records);
            let records: Vec<_> = vec_of_records.iter().flatten().collect();

            assert_eq!(records.len(), 246137);
        });
    }
}

