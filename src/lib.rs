#![allow(unused)]
#![feature(test, try_from)]
#![recursion_limit = "128"]
///! net-parser-rs
///!
///! Network packet parser, also capable of parsing packet capture files (e.g. libpcap) and the
///! associated records.
///!
#[macro_use]
extern crate error_chain;

pub mod errors {
    use crate::layer2;
    use crate::layer3;
    use std;

    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
        foreign_links {
            Io(std::io::Error) #[doc = "Error during IO"];
            Ffi(std::ffi::NulError) #[doc = "Error during FFI conversion"];
            Utf8(std::str::Utf8Error) #[doc = "Error during UTF8 conversion"];
        }
        errors {
            FlowParse {
                display("Parsing failure when converting to stream")
            }
            NomIncomplete(needed: String) {
                display("Not enough data to parse, needed {}", needed)
            }
            NomError(message: String) {
                display("Error parsing: {}", message)
            }
            IncompleteParse(amt: usize) {
                display("Incomplete parse of payload, {} bytes remain", amt)
            }
            L2IncompleteParse(amt: usize) {
                display("Incomplete parse of layer2, {} bytes remain", amt)
            }
            L3IncompleteParse(amt: usize) {
                display("Incomplete parse of layer3, {} bytes remain", amt)
            }
            L4IncompleteParse(amt: usize) {
                display("Incomplete parse of layer4, {} bytes remain", amt)
            }
            EthernetType(value: layer2::ethernet::EthernetTypeId) {
                display("Invalid ethernet type {:?}", value)
            }
            IPv4Length(value: u8) {
                display("Invalid IPv4 length {}", value)
            }
            IPv4Type(value: layer3::InternetProtocolId) {
                display("Invalid ipv4 type {:?}", value)
            }
            IPv6Type(value: layer3::InternetProtocolId) {
                display("Invalid ipv6 type {:?}", value)
            }
            FlowConversion(why: String) {
                display("Could not convert to stream {}", why)
            }
            NotImplemented {
                display("Not implemented yet")
            }
        }
    }

    impl<I, E> From<nom::Err<I, E>> for Error
    where
        I: std::fmt::Debug,
        E: std::fmt::Debug,
    {
        fn from(err: nom::Err<I, E>) -> Error {
            match err {
                nom::Err::Incomplete(nom::Needed::Unknown) => {
                    Error::from_kind(ErrorKind::NomIncomplete("Unknown".to_string()))
                }
                nom::Err::Incomplete(nom::Needed::Size(sz)) => {
                    Error::from_kind(ErrorKind::NomIncomplete(format!("{}", sz)))
                }
                nom::Err::Error(c) => Error::from_kind(ErrorKind::NomError(format!("{:?}", c))),
                nom::Err::Failure(c) => Error::from_kind(ErrorKind::NomError(format!("{:?}", c))),
            }
        }
    }
}

pub mod common;
pub mod flow;
pub mod global_header;
pub mod layer2;
pub mod layer3;
pub mod layer4;
pub mod record;
pub mod stream;

use crate::errors::{Error, ErrorKind};
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
mod tests {
    extern crate test;

    use self::test::Bencher;
    use crate::{flow::FlowExtraction, record::PcapRecord, CaptureParser};
    use nom::Endianness;
    use std::io::prelude::*;
    use std::path::PathBuf;

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

        assert_eq!(converted_records.len(), 129643);
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

            assert_eq!(converted_records.len(), 129643);
        });
    }
}
