# Network Packet Parser (net-parser-rs)
Basic network parser leveraging Rust and [nom](https://github.com/Geal/nom) for safe and efficient packet parsing. Design
influenced by [pktparse-rs](https://github.com/moosingin3space/pktparse-rs/tree/master/src).

## Getting Started
Add net-parser-rs to your dependencies

```toml
[dependencies]
net-parser-rs="0.2"
```

```rust
    #![feature(try_from)]
    extern crate net_parser_rs;

    use net_parser_rs::CaptureParser;
    use std::*;

    //Parse a file with global header and packet records
    let file_bytes = include_bytes!("capture.pcap");
    let records = CaptureParser::parse_file(file_bytes).expect("Could not parse");

    //Parse a sequence of one or more packet records
    let records = CaptureParser::parse_records(record_bytes).expect("Could not parse");

    //Parse a single packet
    let packet = CaptureParser::parse_record(packet_bytes).expect("Could not parse");

    //Convert a packet into flow information
    use net_parser_rs::flow::*;

    let flow = packet.extract_flow().expect("Could not extract flow");
```
