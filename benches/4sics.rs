#![feature(try_from)]
#[macro_use] extern crate criterion;
extern crate net_parser_rs;

use criterion::{Benchmark, Criterion};
use net_parser_rs::convert::*;
use std::io::prelude::*;
use std::path::PathBuf;

const SAMPLE_SIZE: usize = 10;
const RESAMPLES: usize = 10;
const MEASUREMENT_TIME: std::time::Duration = std::time::Duration::from_millis(100);

fn configure_benchmark(bench: Benchmark) -> Benchmark {
    bench.sample_size(SAMPLE_SIZE)
        .measurement_time(MEASUREMENT_TIME)
        .nresamples(RESAMPLES)
}

fn pcap_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources").join("4SICS-GeekLounge-151020.pcap")
}

fn parse_flow(input: &[u8]) {
    let (_, (_, mut records)) = net_parser_rs::CaptureParser::parse_file(input).expect("Failed to parse");
    let records_count = records.len();

    assert!(records_count > 0);

    let flows = PcapRecord::convert_records(records, true).expect("Failed to convert");

    assert!(flows.len() > 0);
}

fn benchmark_parse_flow(c: &mut Criterion) {
    let id = "parse_with_flow";

    let b = Benchmark::new(id, |b| {
        let pcap_reader = std::fs::File::open(pcap_path()).unwrap();

        let bytes = pcap_reader.bytes().map(|b| b.unwrap()).collect::<std::vec::Vec<u8>>();

        b.iter(move || parse_flow(&bytes))
    });

    c.bench(id, configure_benchmark(b));
}

fn parse_pcap(input: &[u8]) {
    let (_, (_, records)) = net_parser_rs::CaptureParser::parse_file(input).expect("Failed to parse");
    assert!(records.len() > 0);
}

fn benchmark_parse_pcap(c: &mut Criterion) {
    let id = "parse";

    let b = Benchmark::new(id, |b| {
        let pcap_reader = std::fs::File::open(pcap_path()).unwrap();

        let bytes = pcap_reader.bytes().map(|b| b.unwrap()).collect::<std::vec::Vec<u8>>();

        b.iter(move || parse_pcap(&bytes))
    });

    c.bench(id, configure_benchmark(b));
}

criterion_group!(benches, benchmark_parse_pcap, benchmark_parse_flow);
criterion_main!(benches);