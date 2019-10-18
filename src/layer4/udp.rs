use crate::Error;
use byteorder::{BigEndian as BE, WriteBytesExt};
use log::*;
use nom::*;
use std::mem::size_of;
use std::io::{Cursor, Write};

const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

pub struct Udp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub checksum: u16,
    pub payload: &'a [u8],
}

impl<'a> Udp<'a> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let inner = Vec::with_capacity(
            size_of::<u16>() * 3
            + self.payload.len()
        );
        let mut writer = Cursor::new(inner);
        writer.write_u16::<BE>(self.src_port).unwrap();
        writer.write_u16::<BE>(self.dst_port).unwrap();
        writer.write_u16::<BE>((self.payload.len() + HEADER_LENGTH) as _).unwrap();
        writer.write_u16::<BE>(self.checksum).unwrap();
        writer.write(self.payload).unwrap();
        writer.into_inner()
    }

    pub fn parse<'b>(input: &'b [u8]) -> Result<(&'b [u8], Udp<'b>), Error> {
        trace!("Available={}", input.len());

        do_parse!(
            input,
            src_port: be_u16
                >> dst_port: be_u16
                >> length: map!(be_u16, |s| (s as usize) - HEADER_LENGTH)
                >> checksum: be_u16
                >> payload: take!(length)
                >> (Udp {
                    src_port,
                    dst_port,
                    checksum,
                    payload
                })
        ).map_err(Error::from)
    }
}

#[cfg(test)]
pub mod tests {
    use hex_slice::AsHex;

    use super::*;

    pub const RAW_DATA: &'static [u8] = &[
        0xC6u8, 0xB7u8, //src port, 50871
        0x00u8, 0x50u8, //dst port, 80
        0x00u8, 0x28u8, //length 40, less header length is payload of 32
        0x00u8, 0x00u8, //checksum
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xfcu8, 0xfdu8, 0xfeu8,
        0xffu8, //payload, 32 bytes
    ];

    #[test]
    fn parse_udp() {
        let _ = env_logger::try_init();

        let (rem, l4) = Udp::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());

        assert_eq!(l4.src_port, 50871);
        assert_eq!(l4.dst_port, 80);
        assert_eq!(
            l4.payload,
            [
                0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
                0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
                0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xfcu8, 0xfdu8,
                0xfeu8, 0xffu8
            ],
            "Payload Mismatch: {:x}",
            l4.payload.as_hex()
        );

        assert_eq!(l4.as_bytes().as_slice(), RAW_DATA);
    }
}
