# Network Packet Decoder (net-decoder)
Basic network decoder leveraging Rust and [nom](https://github.com/Geal/nom) for safe and efficient packet parsing.

## Getting Started
Add net-decoder to your dependencies

```toml
[dependencies]
net-decoder="~0.1"
```

```rust
extern crate net_decoder;

use net_decoder::NetDecoder;

///Parse a file with global header
let records = NetDecoder::parse_file(file_bytes).expect("Could not parse");

///Parse a sequence of one or more packets
let records = NetDecoder::parse(packet_bytes).expect("Could not parse");
```