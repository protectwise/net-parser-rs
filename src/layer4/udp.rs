use crate::{
    layer4::Layer4FlowInfo,
};

use log::*;
use nom::*;
use std;
use std::convert::TryFrom;

const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

pub mod errors {
    use crate::nom_error;
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Nom error while parsing UDP")]
        Nom(#[fail(cause)] nom_error::Error),
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}

pub struct Udp<'a> {
    dst_port: u16,
    src_port: u16,
    payload: &'a [u8],
}

impl<'a> Udp<'a> {
    pub fn dst_port(&self) -> u16 {
        self.dst_port
    }
    pub fn src_port(&self) -> u16 {
        self.src_port
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.payload
    }

    pub fn new(dst_port: u16, src_port: u16, payload: &'a [u8]) -> Udp {
        Udp {
            dst_port,
            src_port,
            payload,
        }
    }

    pub fn parse<'b>(input: &'b [u8]) -> IResult<&'b [u8], Udp<'b>> {
        trace!("Available={}", input.len());

        do_parse!(
            input,
            src_port: be_u16
                >> dst_port: be_u16
                >> length: map!(be_u16, |s| (s as usize) - HEADER_LENGTH)
                >> checksum: be_u16
                >> payload: take!(length)
                >> (Udp {
                    dst_port: dst_port,
                    src_port: src_port,
                    payload: payload
                })
        )
    }
}

impl<'a> TryFrom<Udp<'a>> for Layer4FlowInfo {
    type Error = errors::Error;

    fn try_from(value: Udp<'a>) -> Result<Self, Self::Error> {
        Ok(Layer4FlowInfo {
            dst_port: value.dst_port,
            src_port: value.src_port,
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

        assert_eq!(l4.src_port(), 50871);
        assert_eq!(l4.dst_port(), 80);
        assert_eq!(
            l4.payload(),
            [
                0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
                0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
                0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xfcu8, 0xfdu8,
                0xfeu8, 0xffu8
            ],
            "Payload Mismatch: {:x}",
            l4.payload().as_hex()
        );
    }

    #[test]
    fn convert_udp() {
        let _ = env_logger::try_init();

        let (rem, l4) = Udp::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());

        let info = Layer4FlowInfo::try_from(l4).expect("Could not convert to layer 4 info");

        assert_eq!(info.dst_port, 80);
        assert_eq!(info.src_port, 50871);
    }
}
