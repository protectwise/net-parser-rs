use crate::Error;
use byteorder::{BigEndian as BE, WriteBytesExt};
use log::*;
use nom::{ErrorKind as NomErrorKind, *};
use std::mem::size_of;
use std::io::{Cursor, Write};

const MINIMUM_HEADER_BYTES: usize = 20; //5 32bit words
const MAXIMUM_HEADER_BYTES: usize = 60; //15 32bit words

#[derive(Clone, Copy, Debug)]
pub struct HeaderLengthAndFlags {
    pub inner: u16,
    pub header_length: usize,
    pub flags: u16,
}

#[derive(Clone, Copy, Debug)]
pub struct Tcp<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    pub sequence_number: u32,
    pub acknowledgement_number: u32,
    pub header_length_and_flags: HeaderLengthAndFlags,
    pub window: u16,
    pub check: u16,
    pub urgent: u16,
    pub options: &'a [u8],
    pub payload: &'a [u8],
}

impl<'a> Tcp<'a> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let inner = Vec::with_capacity(
            size_of::<u16>() * 6
            + size_of::<u32>() * 2
            + self.options.len()
            + self.payload.len()
        );
        let mut writer = Cursor::new(inner);
        writer.write_u16::<BE>(self.src_port).unwrap();
        writer.write_u16::<BE>(self.dst_port).unwrap();
        writer.write_u32::<BE>(self.sequence_number).unwrap();
        writer.write_u32::<BE>(self.acknowledgement_number).unwrap();
        writer.write_u16::<BE>(self.header_length_and_flags.inner).unwrap();
        writer.write_u16::<BE>(self.window).unwrap();
        writer.write_u16::<BE>(self.check).unwrap();
        writer.write_u16::<BE>(self.urgent).unwrap();
        writer.write(self.options).unwrap();
        writer.write(self.payload).unwrap();
        writer.into_inner()
    }

    pub fn extract_length(value: u16) -> usize {
        let words = value >> 12;
        (words * 4) as usize
    }

    pub fn parse<'b>(input: &'b [u8]) -> Result<(&'b [u8], Tcp<'b>), Error> {
        trace!("Available={}", input.len());

        do_parse!(
            input,
            src_port: be_u16
                >> dst_port: be_u16
                >> sequence_number: be_u32
                >> acknowledgement_number: be_u32
                >> header_length_and_flags: map_res!(be_u16, |v| {
                    let hl = Tcp::extract_length(v);
                    trace!("Header Length={}", hl);
                    if hl >= MINIMUM_HEADER_BYTES && hl <= MAXIMUM_HEADER_BYTES {
                        let flags = v & 0x01FF; //take lower 9 bits
                        let h = HeaderLengthAndFlags {
                            inner: v,
                            header_length: hl,
                            flags: flags,
                        };
                        Ok(h)
                    } else {
                        Err(error_position!(input, NomErrorKind::CondReduce::<u32>))
                    }
                })
                >> window: be_u16
                >> check: be_u16
                >> urgent: be_u16
                >> options: take!(header_length_and_flags.header_length - MINIMUM_HEADER_BYTES)
                >> payload: rest
                >> (Tcp {
                    src_port: src_port,
                    dst_port: dst_port,
                    sequence_number: sequence_number,
                    acknowledgement_number: acknowledgement_number,
                    header_length_and_flags: header_length_and_flags,
                    window: window,
                    check: check,
                    urgent: urgent,
                    options: options,
                    payload: payload.into()
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
    fn convert_length() {
        assert_eq!(Tcp::extract_length(0x0000u16), 0); //0 words, 0 bytes
        assert_eq!(Tcp::extract_length(0x3000u16), 12); //3 words, 12 bytes
    }

    #[test]
    fn parse_tcp() {
        let _ = env_logger::try_init();

        let (rem, l4) = Tcp::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());

        assert_eq!(l4.dst_port, 80);
        assert_eq!(l4.src_port, 50871);
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
