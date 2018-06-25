use super::prelude::*;
use super::super::flow;
use super::Layer4FlowInfo;

use self::nom::*;
use std;
use std::convert::TryFrom;

const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

pub struct Tcp {
    endianness: Endianness,
    dst_port: u16,
    src_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u16,
    length: usize,
    payload: std::vec::Vec<u8>
}

impl Tcp {
    pub fn endianness(&self) -> Endianness { self.endianness }
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn payload(&self) -> &std::vec::Vec<u8> {
        &self.payload
    }

    fn extract_length(value: u8) -> usize {
        let words = value >> 4;
        (words * 4) as usize
    }

    pub fn new(
        endianness: Endianness,
        dst_port: u16,
        src_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        flags: u16,
        length: usize,
        payload: std::vec::Vec<u8>
    ) -> Tcp {
        Tcp {
            endianness,
            dst_port,
            src_port,
            sequence_number,
            acknowledgement_number,
            flags,
            length,
            payload
        }
    }

    pub fn parse(input: &[u8], endianness: Endianness) -> IResult<&[u8], Tcp> {
        do_parse!(input,
            length: map!(be_u8, |s| Tcp::extract_length(s)) >>
            src_port: be_u16 >>
            dst_port: be_u16 >>
            sequence_number: be_u32 >>
            acknowledgement_number: be_u32 >>
            flags: u16!(endianness) >>
            payload: take!(length) >>
            (
                Tcp {
                    endianness: endianness,
                    dst_port: dst_port,
                    src_port: src_port,
                    sequence_number: sequence_number,
                    acknowledgement_number: acknowledgement_number,
                    flags: flags,
                    length: length,
                    payload: payload.into()
                }
            )
        )
    }
}

impl TryFrom<Tcp> for Layer4FlowInfo {
    type Error = errors::Error;

    fn try_from(value: Tcp) -> Result<Self, Self::Error> {
        Ok(Layer4FlowInfo {
            dst_port: value.dst_port,
            src_port: value.src_port
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate hex_slice;
    use self::hex_slice::AsHex;

    use super::*;

    const RAW_DATA: &'static [u8] = &[
        0x80u8, //length, 8 words (32 bytes)
        0xC6u8, 0xB7u8, //src port, 50871
        0x00u8, 0x50u8, //dst port, 80
        0x00u8, 0x00u8, 0x00u8, 0x01u8, //sequence number, 1
        0x00u8, 0x00u8, 0x00u8, 0x02u8, //acknowledgement number, 2
        0x00u8, 0x00u8, //flags, 0
        0x01u8, 0x02u8, 0x03u8, 0x04u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0xfcu8, 0xfdu8, 0xfeu8, 0xffu8 //payload, 8 words
    ];

    #[test]
    fn parse_tcp() {
        let _ = env_logger::try_init();

        let (rem, l4) = Tcp::parse(RAW_DATA, Endianness::Big).expect("Unable to parse");

        assert!(rem.is_empty());

        assert_eq!(l4.endianness(), Endianness::Big);
        assert_eq!(l4.dst_port(), 80);
        assert_eq!(l4.src_port(), 50871);
        assert_eq!(l4.payload().as_slice(), [0x01u8, 0x02u8, 0x03u8, 0x04u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0xfcu8, 0xfdu8, 0xfeu8, 0xffu8], "Payload Mismatch: {:x}", l4.payload().as_hex());
    }

    #[test]
    fn convert_tcp() {
        let _ = env_logger::try_init();

        let (rem, l4) = Tcp::parse(RAW_DATA, Endianness::Big).expect("Unable to parse");

        assert!(rem.is_empty());

        let info = Layer4FlowInfo::try_from(l4).expect("Could not convert to layer 4 info");

        assert_eq!(info.src_port, 50871);
        assert_eq!(info.dst_port, 80);
    }
}