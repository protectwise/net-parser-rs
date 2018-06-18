use super::prelude::*;

use self::nom::*;
use std;

const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

pub struct Udp<'a> {
    dst_port: u16,
    src_port: u16,
    length: usize,
    payload: &'a [u8]
}

impl<'a> Udp<'a> {
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn length(&self) -> usize {
        self.length
    }
    pub fn payload(&self) -> &[u8] {
        self.payload
    }

    pub(crate) fn parse<'b>(input: &'b [u8], endianness: Endianness) -> IResult<&'b [u8], Udp<'b>> {
        do_parse!(input,

            dst_port: u16!(endianness) >>
            src_port: u16!(endianness) >>
            length: map!(u16!(endianness), |s| {
                let l = s as usize;
                l - HEADER_LENGTH
            }) >>
            payload: take!(length) >>

            (
                Udp {
                    dst_port: dst_port,
                    src_port: src_port,
                    length: length,
                    payload: payload
                }
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_udp() {
        let raw = [
            0xC6u8, 0xB7u8, //dst port, 50871
            0x00u8, 0x50u8, //src port, 80
            0x00u8, 0x40u8, //length 64, less header length is payload of 32
            0x01u8, 0x02u8, 0x03u8, 0x04u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0x00u8, 0x00u8, 0x00u8, 0x00u8,
            0xfcu8, 0xfdu8, 0xfeu8, 0xffu8 //payload, 32 bytes
        ];

        let (rem, l4) = Udp::parse(raw, Endianness::Big).expect("Unable to parse");

        assert!(rem.is_empty());

        assert_eq!(l4.dst_port, 50871);
        assert_eq!(l4.src_port, 80);
        assert_eq!(l4.length, 32);
        assert_eq!(l4.payload, b"01020304000000000000000000000000000000000000000000000000fcfdfeff")
    }
}