use crate::{
    flow,
    layer4::Layer4FlowInfo,
    prelude::*
};

use nom::{
    be_u16,
    be_u32,
    Err as NomError,
    ErrorKind as NomErrorKind,
    IResult,
    rest
};
use std;
use std::convert::TryFrom;

const MINIMUM_HEADER_BYTES: usize = 20; //5 32bit words
const MAXIMUM_HEADER_BYTES: usize = 60; //15 32bit words

pub struct Tcp<'a> {
    dst_port: u16,
    src_port: u16,
    sequence_number: u32,
    acknowledgement_number: u32,
    flags: u16,
    payload: &'a [u8]
}

impl<'a> Tcp<'a> {
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.payload
    }

    pub fn extract_length(value: u16) -> usize {
        let words = value >> 12;
        (words * 4) as usize
    }

    pub fn new(
        dst_port: u16,
        src_port: u16,
        sequence_number: u32,
        acknowledgement_number: u32,
        flags: u16,
        payload: &'a [u8]
    ) -> Tcp {
        Tcp {
            dst_port,
            src_port,
            sequence_number,
            acknowledgement_number,
            flags,
            payload
        }
    }

    pub fn parse<'b>(input: &'b [u8]) -> IResult<&'b [u8], Tcp<'b>> {
        trace!("Available={}", input.len());

        do_parse!(input,

            src_port: be_u16 >>
            dst_port: be_u16 >>
            sequence_number: be_u32 >>
            acknowledgement_number: be_u32 >>
            header_length_and_flags: map_res!(be_u16, |v| {
                let hl = Tcp::extract_length(v);
                trace!("Header Length={}", hl);
                if hl >= MINIMUM_HEADER_BYTES && hl <= MAXIMUM_HEADER_BYTES {
                    let flags = v & 0x01FF; //take lower 9 bits
                    Ok( (hl, flags) ) as Result<(usize, u16), nom::Context<&[u8]>>
                } else {
                    Err(error_position!(input, NomErrorKind::CondReduce::<u32>))
                }
            }) >>
            window: be_u16 >>
            check: be_u16 >>
            urgent: be_u16 >>
            options: take!(header_length_and_flags.0 - MINIMUM_HEADER_BYTES) >>
            payload: rest >>
            (
                Tcp {
                    dst_port: dst_port,
                    src_port: src_port,
                    sequence_number: sequence_number,
                    acknowledgement_number: acknowledgement_number,
                    flags: header_length_and_flags.1,
                    payload: payload.into()
                }
            )
        )
    }
}

impl<'a> TryFrom<Tcp<'a>> for Layer4FlowInfo {
    type Error = errors::Error;

    fn try_from(value: Tcp<'a>) -> Result<Self, Self::Error> {
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
    fn convert_length() {
        assert_eq!(Tcp::extract_length(0x0000u16), 0); //0 words, 0 bytes
        assert_eq!(Tcp::extract_length(0x3000u16), 12); //3 words, 12 bytes
    }

    #[test]
    fn parse_tcp() {
        let _ = env_logger::try_init();

        let (rem, l4) = Tcp::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());

        assert_eq!(l4.dst_port(), 80);
        assert_eq!(l4.src_port(), 50871);
        assert_eq!(l4.payload(), [0x01u8, 0x02u8, 0x03u8, 0x04u8,
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

        let (rem, l4) = Tcp::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());

        let info = Layer4FlowInfo::try_from(l4).expect("Could not convert to layer 4 info");

        assert_eq!(info.src_port, 50871);
        assert_eq!(info.dst_port, 80);
    }
}