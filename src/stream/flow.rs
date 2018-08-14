use crate::{
    prelude::*,
    errors::Error,
    flow::{
        Flow,
        FlowExtraction
    }
};

use futures::{
    Poll,
    Stream
};
use std::{
    self,
    convert::{
        From,
        TryInto
    },
    mem::{
        PinMut
    }
};

pub struct FlowRecord<R> where R: FlowExtraction {
    record: R,
    flow: Flow
}

pub struct FlowStream<S>
    where S: Stream,
    S::Item: FlowExtraction
{
    inner: S
}

impl<S> FlowStream<S>
    where S: Stream,
    S::Item: FlowExtraction
{
    unsafe_pinned!(inner: S);

    pub fn new(
        inner: S
    ) -> FlowStream<S>
    {
        FlowStream {
            inner: inner
        }
    }
}

impl<S> Stream for FlowStream<S>
    where S: Stream,
    S::Item: FlowExtraction
{
    type Item=FlowRecord<S::Item>;

    fn poll_next(
        mut self: PinMut<Self>,
        cx: &mut std::task::Context,
    ) -> Poll<Option<Self::Item>> {
        loop {
            let v = self.inner().poll_next(cx);
            match v {
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(mut v)) => {
                    match v.extract_flow() {
                        Err(e) => {
                            debug!("Failed to convert value: {:?}", e)
                        }
                        Ok(f) => {
                            let res = FlowRecord {
                                record: v,
                                flow: f
                            };
                            return Poll::Ready(Some(res))
                        }
                    }
                }
            }
        }
    }
}

pub trait WithExtraction: Stream {
    fn extract<'a>(self) -> FlowStream<Self>
        where Self: Stream + Sized,
        Self::Item: FlowExtraction
    {
        FlowStream::new(self)
    }
}

impl<T: ?Sized> WithExtraction for T where T: Stream {}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate test;

    use super::*;
    use super::super::super::{
        record::PcapRecord,
        CaptureParser
    };

    use futures::{
        executor::ThreadPool,
        stream as futures_stream,
        StreamExt
    };
    use nom::Endianness;
    use self::test::Bencher;
    use std::{
        io::Read,
        path::PathBuf
    };

    #[test]
    fn create_stream_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources").join("4SICS-GeekLounge-151020.pcap");

        let pcap_reader = std::fs::File::open(pcap_path.clone()).expect(&format!("Failed to open pcap path {:?}", pcap_path));

        let bytes = pcap_reader.bytes().map(|b| b.unwrap()).collect::<std::vec::Vec<u8>>();

        let (rem, (header, mut records)) = CaptureParser::parse_file(&bytes).expect("Failed to parse");

        assert_eq!(header.endianness(), Endianness::Little);
        assert_eq!(records.len(), 246137);

        let mut rt = ThreadPool::new().expect("Failed to create threadpool");

        let fut_flows = futures_stream::iter(records)
            .extract()
            .collect::<Vec<_>>();

        let flows = rt.run(fut_flows);

        assert_eq!(flows.len(), 129643);
    }

    #[bench]
    fn bench_create_stream_from_file(b: &mut Bencher) {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources").join("4SICS-GeekLounge-151020.pcap");

        b.iter(|| {
            let pcap_reader = std::fs::File::open(pcap_path.clone()).expect(&format!("Failed to open pcap path {:?}", pcap_path));

            let bytes = pcap_reader.bytes().map(|b| b.unwrap()).collect::<std::vec::Vec<u8>>();

            let (rem, (header, mut records)) = CaptureParser::parse_file(&bytes).expect("Failed to parse");

            assert_eq!(header.endianness(), Endianness::Little);
            assert_eq!(records.len(), 246137);

            let mut rt = ThreadPool::new().expect("Failed to create threadpool");

            let fut_flows = futures_stream::iter(records)
                .extract()
                .collect::<Vec<_>>();

            let flows = rt.run(fut_flows);

            assert_eq!(flows.len(), 129643);
        });
    }
}