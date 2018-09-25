use crate::{
    errors::Error,
    flow::{
        Flow,
        FlowExtraction
    }
};

use futures::{
    self,
    Async,
    Poll,
    Stream
};
use std::{
    self,
    convert::{
        From,
        TryInto
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
    type Error=S::Error;

    fn poll(
        &mut self
    ) -> Poll<Option<Self::Item>, Self::Error> {
        loop {
            if let Some(mut v) = try_ready!(self.inner.poll()) {
                match v.extract_flow() {
                    Err(e) => {
                        debug!("Failed to convert value: {:?}", e)
                    }
                    Ok(f) => {
                        let res = FlowRecord {
                            record: v,
                            flow: f
                        };
                        return Ok(Async::Ready(Some(res)))
                    }
                }
            } else {
                return Ok(Async::Ready(None));
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
    extern crate test;

    use super::*;

    use crate::{
        record::PcapRecord,
        CaptureParser
    };

    use futures::{
        stream as futures_stream,
        Future
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

        let fut_flows = futures_stream::iter_ok::<Vec<PcapRecord>, Error>(records)
            .extract()
            .collect();

        let flows = fut_flows.wait().expect("Failed to run");

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

            let fut_flows = futures_stream::iter_ok::<Vec<PcapRecord>, Error>(records)
                .extract()
                .collect();

            let flows = fut_flows.wait().expect("Failed to run");

            assert_eq!(flows.len(), 129643);
        });
    }
}