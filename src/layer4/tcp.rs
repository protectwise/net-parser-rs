use super::prelude::*;

use self::nom::*;
use std;
const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

pub struct Tcp<'a> {
    dst_port: u16,
    src_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u16,
    length: usize,
    payload: &'a [u8]
}

impl<'a> Tcp<'a> {
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn length(&self) -> usize {
        self.length
    }
    pub fn payload(&self) -> &'a [u8] {
        self.payload
    }

    fn extract_length(value: u8) -> usize {
        let words = value >> 4;
        (words * 4) as usize
    }

    pub(crate) fn parse<'b>(input: &'b [u8], endianness: Endianness) -> IResult<&'b [u8], Tcp<'b>> {
        do_parse!(input,
            length: map!(be_u8, |s| Tcp::extract_length(s)) >>
            src_port: u16!(endianness) >>
            dst_port: u16!(endianness) >>
            sequence_number: u32!(endianness) >>
            acknowledgement_number: u32!(endianness) >>
            flags: u16!(endianness) >>
            payload: take!(length) >>
            (
                Tcp {
                    dst_port: dst_port,
                    src_port: src_port,
                    sequence_number: sequence_number,
                    acknowledgement_number: acknowledgement_number,
                    flags: flags,
                    length: length,
                    payload: payload
                }
            )
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate hex_slice;
    use self::hex_slice::AsHex;

    use super::*;

    #[test]
    fn parse_tcp() {
        let _ = env_logger::try_init();

        let raw = [
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

        let (rem, l4) = Tcp::parse(&raw, Endianness::Big).expect("Unable to parse");

        assert!(rem.is_empty());

        assert_eq!(l4.dst_port(), 80);
        assert_eq!(l4.src_port(), 50871);
        assert_eq!(l4.length(), 32);
        assert_eq!(l4.payload(), [0x01u8, 0x02u8, 0x03u8, 0x04u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0xfcu8, 0xfdu8, 0xfeu8, 0xffu8], "Payload Mismatch: {:x}", l4.payload().as_hex());
    }
}