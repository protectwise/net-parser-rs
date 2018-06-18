# Network Packet Parser (net-parser-rs)
Basic network parser leveraging Rust and [nom](https://github.com/Geal/nom) for safe and efficient packet parsing.

## Getting Started
Add net-parser-rs to your dependencies

```toml
[dependencies]
net-parser-rs="~0.1"
```

```rust
extern crate net_parser_rs;

use net_parser_rs::NetworkParser;
use std::*;

///Parse a file with global header
let file_bytes = include_bytes!("capture.pcap");
let records = NetworkParser::parse_file(file_bytes).expect("Could not parse");

///Parse a sequence of one or more packets
let records = NetworkParser::parse(packet_bytes).expect("Could not parse");
```
