use criterion::{criterion_group, criterion_main, Criterion};
use nom::Endianness;
use net_parser_rs::CaptureParser;
use std::io::Read;
use std::path::PathBuf;

fn bench_4sics(c: &mut Criterion) {
    let benchmark = criterion::Benchmark::new("parse", |b| {
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

        b.iter(|| {
            let (_, (header, records)) =
                CaptureParser::parse_file(&bytes).expect("Failed to parse");

            assert_eq!(header.endianness(), Endianness::Little);
            assert_eq!(records.len(), 246137);
        });
    });

    c.bench(
        "parse",
        benchmark
            .sample_size(10)
            .nresamples(1)
            .measurement_time(std::time::Duration::from_secs(15)),
    );

    let benchmark = criterion::Benchmark::new("extract", |b| {
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

        b.iter(|| {
            let (_, (header, records)) =
                crate::CaptureParser::parse_file(&bytes).expect("Failed to parse");

            assert_eq!(header.endianness(), nom::Endianness::Little);
            assert_eq!(records.len(), 246137);

            let converted_records = net_parser_rs::flow::convert_records(records);

            assert_eq!(converted_records.len(), 236527);
        });
    });

    c.bench(
        "extract",
        benchmark
            .sample_size(10)
            .nresamples(1)
            .measurement_time(std::time::Duration::from_secs(15)),
    );
}

criterion_group!(benches, bench_4sics);

// Benchmark: cargo bench --verbose
//parse                   time:   [12.266 ms 11.450 ms 12.266 ms]
//extract                 time:   [64.922 ms 74.091 ms 64.922 ms]
criterion_main!(benches);
