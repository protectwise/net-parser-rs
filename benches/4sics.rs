#![feature(try_from)]
#[macro_use] extern crate criterion;
extern crate net_parser_rs;

use criterion::Criterion;
use net_parser_rs::convert::*;
use std::io::prelude::*;
use std::path::PathBuf;

fn pcap_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources").join("4SICS-GeekLounge-151020.pcap")
}

fn parse_flow(input: &[u8]) {
    let (_, (_, mut records)) = net_parser_rs::CaptureParser::parse_file(input).expect("Failed to parse");
    let records_count = records.len();

    assert!(records_count > 0);

    let mut flow_count = 0;

    while let Some(record) = records.pop() {
        if let Ok(_) = Flow::try_from(record) {
            flow_count += 1;
        }
    };

    assert!(flow_count > 0);
}

fn benchmark_parse_flow(c: &mut Criterion) {
    let pcap_reader = std::fs::File::open(pcap_path()).unwrap();

    let bytes = pcap_reader.bytes().map(|b| b.unwrap()).collect::<std::vec::Vec<u8>>();

    c.bench_function("parse with flow", move |b| b.iter(|| parse_flow(&bytes)));
}

fn parse_pcap(input: &[u8]) {
    let (_, (_, records)) = net_parser_rs::CaptureParser::parse_file(input).expect("Failed to parse");
    assert!(records.len() > 0);
}

fn benchmark_parse_pcap(c: &mut Criterion) {
    let pcap_reader = std::fs::File::open(pcap_path()).unwrap();

    let bytes = pcap_reader.bytes().map(|b| b.unwrap()).collect::<std::vec::Vec<u8>>();

    c.bench_function("parse", move |b| b.iter(|| parse_pcap(&bytes)));
}

criterion_group!(benches, benchmark_parse_pcap, benchmark_parse_flow);
criterion_main!(benches);