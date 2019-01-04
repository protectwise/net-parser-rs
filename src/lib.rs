#![allow(unused)]
#![feature(test, try_from)]
///! net-parser-rs
///!
///! Network packet parser, also capable of parsing packet capture files (e.g. libpcap) and the
///! associated records.
///!

pub mod common;
pub mod errors;
pub mod flow;
pub mod global_header;
pub mod layer2;
pub mod layer3;
pub mod layer4;
pub mod nom_error;
pub mod record;
pub mod stream;

use log::*;
use nom::*;

///
/// Primary utility for parsing packet captures, either from file, bytes, or interfaces.
///
/// ```text
///    #![feature(try_from)]
///
///    use net_parser_rs::NetworkParser;
///    use std::*;
///
///    //Parse a file with global header and packet records
///    let file_bytes = include_bytes!("capture.pcap");
///    let records = CaptureParser::parse_file(file_bytes).expect("Could not parse");
///
///    //Parse a sequence of one or more packet records
///    let records = CaptureParser::parse_records(record_bytes).expect("Could not parse");
///
///    //Parse a single packet
///    let packet = CaptureParser::parse_record(packet_bytes).expect("Could not parse");
///
///    //Convert a packet into stream information
///    use net_parser_rs::convert::*;
///
///    let stream = Flow::try_from(packet).expect("Could not convert packet");
///```
///
pub struct CaptureParser;

impl CaptureParser {
    ///
    /// Parse a slice of bytes that start with libpcap file format header (https://wiki.wireshark.org/Development/LibpcapFileFormat)
    ///
    pub fn parse_file<'a>(
        input: &'a [u8],
    ) -> IResult<
        &'a [u8],
        (
            global_header::GlobalHeader,
            std::vec::Vec<record::PcapRecord<'a>>,
        ),
    > {
        let header_res = global_header::GlobalHeader::parse(input);

        header_res.and_then(|r| {
            let (rem, header) = r;

            debug!(
                "Global header version {}.{}, with endianness {:?}",
                header.version_major(),
                header.version_minor(),
                header.endianness()
            );

            CaptureParser::parse_records(rem, header.endianness()).map(|records_res| {
                let (records_rem, records) = records_res;

                trace!("{} bytes left for record parsing", records_rem.len());

                (records_rem, (header, records))
            })
        })
    }

    ///
    /// Parse a slice of bytes that correspond to a set of records, without libcap file format
    /// header (https://wiki.wireshark.org/Development/LibpcapFileFormat). Endianness of the byte
    /// slice must be known.
    ///
    pub fn parse_records<'a>(
        input: &'a [u8],
        endianness: Endianness,
    ) -> IResult<&'a [u8], std::vec::Vec<record::PcapRecord<'a>>> {
        let mut records: std::vec::Vec<record::PcapRecord> = vec![];
        let mut current = input;

        trace!("{} bytes left for record parsing", current.len());

        loop {
            match record::PcapRecord::parse(current, endianness) {
                Ok((rem, r)) => {
                    current = rem;
                    trace!("{} bytes left for record parsing", current.len());
                    records.push(r);
                }
                Err(nom::Err::Incomplete(nom::Needed::Size(s))) => {
                    debug!("Needed {} bytes for parsing, only had {}", s, current.len());
                    break;
                }
                Err(nom::Err::Incomplete(nom::Needed::Unknown)) => {
                    debug!(
                        "Needed unknown number of bytes for parsing, only had {}",
                        current.len()
                    );
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok((current, records))
    }

    ///
    /// Parse a slice of bytes as a single record. Endianness must be known.
    ///
    pub fn parse_record<'a>(
        input: &'a [u8],
        endianness: Endianness,
    ) -> IResult<&'a [u8], record::PcapRecord<'a>> {
        record::PcapRecord::parse(input, endianness)
    }
}

#[cfg(test)]
pub mod tests {
    extern crate test;

    use self::test::Bencher;
    use crate::{flow::FlowExtraction, record::PcapRecord, CaptureParser};
    use nom::Endianness;
    use std::io::prelude::*;
    use std::path::PathBuf;


    pub mod util {
        extern crate hex;
        extern crate regex;
        use regex::Regex;

        #[test]
        fn test_hex_dump() {
            let bytes = parse_hex_dump(r"
            # Comment line
            0090   34 35 36 37                                      4567
        ").expect("Failed to parse bytes");
            let b = b"4567".to_vec().into_boxed_slice();
            assert_eq!(bytes.len(), 4)
        }

        /// Parses a "Hex + ASCII Dump" from Wireshark to extract the payload bits.
        /// Example:
        /// ```rust
        ///         let bytes = parse_hex_dump(r##"
        ///            # Frame 3: 148 bytes on wire (1184 bits), 148 bytes captured (1184 bits) on interface 0
        ///            # Ethernet II, Src: CadmusCo_ae:4d:62 (08:00:27:ae:4d:62), Dst: CadmusCo_f2:1d:8c (08:00:27:f2:1d:8c)
        ///            # Internet Protocol Version 4, Src: 192.168.56.11, Dst: 192.168.56.12
        ///            # User Datagram Protocol, Src Port: 48134 (48134), Dst Port: 4789 (4789)
        ///            # Virtual eXtensible Local Area Network
        ///            # Ethernet II, Src: ba:09:2b:6e:f8:be (ba:09:2b:6e:f8:be), Dst: 4a:7f:01:3b:a2:71 (4a:7f:01:3b:a2:71)
        ///            # Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2
        ///            # Internet Control Message Protocol
        ///            0000   08 00 27 f2 1d 8c 08 00 27 ae 4d 62 08 00 45 00  ..'.....'.Mb..E.
        ///            0010   00 86 d9 99 40 00 40 11 6f 65 c0 a8 38 0b c0 a8  ....@.@.oe..8...
        ///            0020   38 0c bc 06 12 b5 00 72 00 00 08 00 00 00 00 00  8......r........
        ///            0030   7b 00 4a 7f 01 3b a2 71 ba 09 2b 6e f8 be 08 00  {.J..;.q..+n....
        ///            0040   45 00 00 54 2f 4f 40 00 40 01 f7 57 0a 00 00 01  E..T/O@.@..W....
        ///            0050   0a 00 00 02 08 00 4c 8a 0d 3d 00 01 a3 8c 7c 57  ......L..=....|W
        ///            0060   00 00 00 00 b5 80 0a 00 00 00 00 00 10 11 12 13  ................
        ///            0070   14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23  ............ !"#
        ///            0080   24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33  $%&'()*+,-./0123
        ///            0090   34 35 36 37                                      4567
        ///        "##).unwrap();
        ///        assert_eq!(bytes.len(), 148);
        /// ```
        pub fn parse_hex_dump(input: &str) -> Result<Vec<u8>, hex::FromHexError> {
            let hex_reg: Regex = Regex::new(r"(?m)^\s*[0-9a-fA-F]{3,}\s+((?:[0-9a-fA-F]{2}\s){1,16}).*?$").unwrap();

            let mut response = vec!();
            for cap in hex_reg.captures_iter(input) {
                let c = Vec::from(cap[1].replace(" ", ""));

                let mut decode = hex::decode(c)?;
                response.append(&mut decode);
            }
            Ok(response)
        }
    }

    const RAW_DATA: &'static [u8] = &[
        0x4du8, 0x3c, 0x2b, 0x1au8, //magic number
        0x00u8, 0x04u8, //version major, 4
        0x00u8, 0x02u8, //version minor, 2
        0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
        0x00u8, 0x00u8, 0x00u8, 0x04u8, //sig figs, 4
        0x00u8, 0x00u8, 0x06u8, 0x13u8, //snap length, 1555
        0x00u8, 0x00u8, 0x00u8, 0x02u8, //network, 2
        //record
        0x5Bu8, 0x11u8, 0x6Du8, 0xE3u8, //seconds, 1527868899
        0x00u8, 0x02u8, 0x51u8, 0xF5u8, //microseconds, 152053
        0x00u8, 0x00u8, 0x00u8,
        0x56u8, //actual length, 86: 14 (ethernet) + 20 (ipv4 header) + 20 (tcp header) + 32 (tcp payload)
        0x00u8, 0x00u8, 0x04u8, 0xD0u8, //original length, 1232
        //ethernet
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
        0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
        0x08u8, 0x00u8, //ipv4
        //ipv4
        0x45u8, //version and header length
        0x00u8, //tos
        0x00u8, 0x48u8, //length, 20 bytes for header, 52 bytes for ethernet
        0x00u8, 0x00u8, //id
        0x00u8, 0x00u8, //flags
        0x64u8, //ttl
        0x06u8, //protocol, tcp
        0x00u8, 0x00u8, //checksum
        0x01u8, 0x02u8, 0x03u8, 0x04u8, //src ip 1.2.3.4
        0x0Au8, 0x0Bu8, 0x0Cu8, 0x0Du8, //dst ip 10.11.12.13
        //tcp
        0xC6u8, 0xB7u8, //src port, 50871
        0x00u8, 0x50u8, //dst port, 80
        0x00u8, 0x00u8, 0x00u8, 0x01u8, //sequence number, 1
        0x00u8, 0x00u8, 0x00u8, 0x02u8, //acknowledgement number, 2
        0x50u8, 0x00u8, //header and flags, 0
        0x00u8, 0x00u8, //window
        0x00u8, 0x00u8, //check
        0x00u8, 0x00u8, //urgent
        //no options
        //payload
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xfcu8, 0xfdu8, 0xfeu8,
        0xffu8, //payload, 8 words
    ];

    #[test]
    fn file_bytes_parse() {
        let _ = env_logger::try_init();

        let (rem, (header, records)) =
            CaptureParser::parse_file(RAW_DATA).expect("Failed to parse");

        assert!(rem.is_empty());

        assert_eq!(header.endianness(), Endianness::Big);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn convert_packet() {
        let _ = env_logger::try_init();

        let (rem, (header, mut records)) =
            CaptureParser::parse_file(RAW_DATA).expect("Failed to parse");

        assert!(rem.is_empty());

        let mut record = records.pop().unwrap();
        let flow = record.extract_flow().expect("Failed to extract flow");

        assert_eq!(flow.source().port(), 50871);
        assert_eq!(flow.destination().port(), 80);
    }

    #[test]
    fn file_parse() {
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

        let (rem, (header, records)) = CaptureParser::parse_file(&bytes).expect("Failed to parse");

        assert_eq!(header.endianness(), Endianness::Little);
        assert_eq!(records.len(), 246137);
    }

    #[test]
    fn file_convert() {
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

        let converted_records = PcapRecord::convert_records(records);

        assert_eq!(converted_records.len(), 236527);
    }

    #[bench]
    fn bench_parse(b: &mut Bencher) {
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
            let (rem, (header, records)) =
                CaptureParser::parse_file(&bytes).expect("Failed to parse");

            assert_eq!(header.endianness(), Endianness::Little);
            assert_eq!(records.len(), 246137);
        });
    }

    #[bench]
    fn bench_parse_convert(b: &mut Bencher) {
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
            let (rem, (header, mut records)) =
                CaptureParser::parse_file(&bytes).expect("Failed to parse");

            assert_eq!(header.endianness(), Endianness::Little);
            assert_eq!(records.len(), 246137);

            let converted_records = PcapRecord::convert_records(records);

            assert_eq!(converted_records.len(), 236527);
        });
    }
}
