use crate::{
    errors::Error,
    extraction::flow::{Flow, FlowExtraction},
};

use futures::{self, Poll, stream::Stream};
use log::*;
use std::{
    self,
    convert::{From, TryInto},
    pin::Pin
};

pub struct FlowRecord<R>
where
    R: FlowExtraction,
{
    record: R,
    flow: Flow,
}

pub struct ExtractionStream<S>
where
    S: Stream,
    S::Item: FlowExtraction,
{
    inner: S,
}

impl<S> ExtractionStream<S>
where
    S: Stream,
    S::Item: FlowExtraction,
{
    pub fn new(inner: S) -> ExtractionStream<S> {
        ExtractionStream { inner: inner }
    }
}

impl<S> Stream for ExtractionStream<S>
where
    S: Stream + Unpin,
    S::Item: FlowExtraction,
{
    type Item = FlowRecord<S::Item>;

    fn poll_next(mut self: std::pin::Pin<&mut Self>, lw: &std::task::LocalWaker) -> futures::Poll<Option<Self::Item>> {
        let this = &mut *self;
        loop {
            match Pin::new(&mut this.inner).poll_next(lw) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => return Poll::Ready(None),
                Poll::Ready(Some(mut v)) => {
                    match v.extract_flow() {
                        Err(e) => debug!("Failed to convert value: {:?}", e),
                        Ok(f) => {
                            let res = FlowRecord { record: v, flow: f };
                            return Poll::Ready(Some(res));
                        }
                    }
                }
            }
        }
    }
}

pub trait WithExtraction: Stream {
    fn extract(self) -> ExtractionStream<Self>
    where
        Self: Stream + Sized,
        Self::Item: FlowExtraction,
    {
        ExtractionStream::new(self)
    }
}

impl<T: ?Sized> WithExtraction for T where T: Stream {}

#[cfg(test)]
mod tests {
    extern crate test;

    use super::*;

    use crate::{parse::record::PcapRecord, CaptureParser};

    use self::test::Bencher;
    use futures::{stream as futures_stream, Future, StreamExt};
    use nom::Endianness;
    use std::{io::Read, path::PathBuf};

    #[test]
    fn create_stream_from_file() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        let pcap_reader = std::fs::File::open(pcap_path.clone())
            .expect(&format!("Failed to open pcap path {:?}", pcap_path));

        let bytes = pcap_reader
            .bytes()
            .map(|b| b.unwrap())
            .collect::<std::vec::Vec<u8>>();

        let (rem, (header, mut records)) =
            CaptureParser::parse_file(&bytes).expect("Failed to parse");

        assert_eq!(header.endianness(), Endianness::Little);
        assert_eq!(records.len(), 246137);

        let fut_flows = async {
            let flows: Vec<_> = await!(futures_stream::iter(records)
                .extract()
                .collect());
            flows
        };

        let flows = futures::executor::block_on(fut_flows);

        assert_eq!(flows.len(), 236527);
    }

    #[bench]
    fn bench_create_stream_from_file(b: &mut Bencher) {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        b.iter(|| {
            let pcap_reader = std::fs::File::open(pcap_path.clone())
                .expect(&format!("Failed to open pcap path {:?}", pcap_path));

            let bytes = pcap_reader
                .bytes()
                .map(|b| b.unwrap())
                .collect::<std::vec::Vec<u8>>();

            let (rem, (header, mut records)) =
                CaptureParser::parse_file(&bytes).expect("Failed to parse");

            assert_eq!(header.endianness(), Endianness::Little);
            assert_eq!(records.len(), 246137);

            let fut_flows = async {
                let flows: Vec<_> = await!(futures_stream::iter(records)
                    .extract()
                    .collect());
                flows
            };

            let flows = futures::executor::block_on(fut_flows);

            assert_eq!(flows.len(), 236527);
        });
    }
}
