#![allow(unused)]
#![feature(trace_macros)]
#[macro_use] pub extern crate arrayref;
#[macro_use] pub extern crate error_chain;
#[macro_use] pub extern crate nom;

pub mod prelude {
    pub use super::arrayref::*;
    pub use super::common::*;
    pub use super::nom;
    pub use super::errors;
}

pub mod errors {
    use std;

    // Create the Error, ErrorKind, ResultExt, and Result types
    error_chain! {
        foreign_links {
            Io(std::io::Error) #[doc = "Error during IO"];
            Ffi(std::ffi::NulError) #[doc = "Error during FFI conversion"];
            Utf8(std::str::Utf8Error) #[doc = "Error during UTF8 conversion"];
        }
        errors {
            Nom(value: u32) {
                display("Error parsing {}", value)
            }
            EthernetType(value: u16) {
                display("Invalid ethernet type {}", value)
            }
            InvalidIPv4Length(value: u8) {
                display("Invalid IPv4 length {}", value)
            }
            NotImplemented {
                display("Not implemented yet")
            }
        }
    }

    impl From<u32> for Error {
        fn from(v: u32) -> Self {
            Error::from_kind(ErrorKind::Nom(v))
        }
    }
}

pub mod common;
//pub mod flow;
pub mod global_header;
pub mod layer2;
pub mod layer3;
pub mod layer4;
pub mod record;

use errors::*;
use nom::*;

struct NetworkParser<'a> {
    global_header: global_header::GlobalHeader,
    records: std::vec::Vec<record::PcapRecord<'a>>
}

impl<'a> NetworkParser<'a> {
    pub fn global_header(&'a self) -> &'a global_header::GlobalHeader {
        &self.global_header
    }
    pub fn records(&'a self) -> &'a std::vec::Vec<record::PcapRecord<'a>> {
        &self.records
    }
    pub fn parse_file<'b>(input: &'b [u8]) -> IResult<&[u8], NetworkParser<'b>> {
        let header_res = global_header::GlobalHeader::parse(input);

        header_res.and_then(|r| {
            let (rem, header) = r;

            NetworkParser::parse_records(rem, header.endianness()).map(|records_res| {
                let (records_rem, records) = records_res;

                (records_rem, NetworkParser {
                    global_header: header,
                    records: records
                })
            })
        })
    }

    pub fn parse_records<'b>(input: &'b [u8], endianness: Endianness) -> IResult<&'b [u8], std::vec::Vec<record::PcapRecord<'b>>> {
        let mut records: std::vec::Vec<record::PcapRecord<'b>> = vec![];
        let mut current = input;

        loop {
            match record::PcapRecord::parse(current, endianness) {
                Ok( (rem, r) ) => {
                    current = rem;
                    records.push(r);
                }
                Err(nom::Err::Incomplete(_)) => {
                    break
                }
                Err(e) => return Err(e)
            }
        };

        Ok( (current, records) )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_parse() {
        let raw = [
            0xa1u8, 0xb2, 0xc3, 0xd4u8, //magic number
            0x04u8, //version major, 4
            0x02u8, //version minor, 2
            0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
            0x00u8, 0x00u8, 0x00u8, 0x04u8, //sig figs, 4
            0x00u8, 0x00u8, 0x06u8, 0x13u8, //snap length, 1555
            0x00u8, 0x00u8, 0x00u8, 0x02u8, //network, 2
            //ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
            0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
            0x00u8, 0x08u8, //payload ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8
        ];

        let (rem, f) = NetworkParser::parse_file(raw).expect("Failed to parse");

        assert!(rem.is_empty());

        assert_eq!(f.global_header().endianness(), Endianness::Big);
        assert_eq!(f.records().size(), 1);
    }
}