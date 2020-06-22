use crate::Error;
use crate::layer3::InternetProtocolId;

use arrayref::array_ref;
use byteorder::{BigEndian as BE, WriteBytesExt};
use log::*;
use nom::*;
use std::mem::size_of;
use std::net::IpAddr;
use std::io::{Cursor, Write};
use failure::_core::ops::Deref;

const ADDRESS_LENGTH: usize = 4;

pub const HEADER_LENGTH: usize = 20;

#[derive(Clone, Debug)]
pub enum Payload<'a> {
    Slice(&'a [u8]),
    Owned(Vec<u8>),
}

impl <'a> Deref for Payload<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl <'a> Payload<'a> {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Payload::Slice(s) => {
                *s
            },
            Payload::Owned(v) => {
                v.as_slice()
            }
        }
    }
}

#[derive(Clone, Debug)]
pub struct IPv4<'a> {
    pub version_and_length: u8,
    pub tos: u8,
    pub raw_length: u16,
    pub id: u16,
    pub flags: u16,
    pub ttl: u8,
    pub protocol: InternetProtocolId,
    pub checksum: u16,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub payload: Payload<'a>,
    pub options: Option<&'a [u8]>,
    pub padding: Option<&'a [u8]>,
}

fn to_ip_address(i: &[u8]) -> IpAddr {
    let ipv4 = std::net::Ipv4Addr::from(array_ref![i, 0, ADDRESS_LENGTH].clone());
    IpAddr::V4(ipv4)
}

named!(
    ipv4_address<&[u8], std::net::IpAddr>,
    map!(take!(ADDRESS_LENGTH), to_ip_address)
);

impl<'a> IPv4<'a> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let inner = Vec::with_capacity(
            size_of::<u8>() * 4
            + size_of::<u16>() * 4
            + 4 * 2
            + self.payload.len()
            + self.options.map(|i| i.len()).unwrap_or(0)
            + self.padding.map(|i| i.len()).unwrap_or(0)
        );
        let mut writer = Cursor::new(inner);
        writer.write_u8(self.version_and_length).unwrap();
        writer.write_u8(self.tos).unwrap();
        writer.write_u16::<BE>(self.raw_length).unwrap();
        writer.write_u16::<BE>(self.id).unwrap();
        writer.write_u16::<BE>(self.flags).unwrap();
        writer.write_u8(self.ttl).unwrap();
        writer.write_u8(self.protocol.value()).unwrap();
        writer.write_u16::<BE>(self.checksum).unwrap();
        if let IpAddr::V4(v) = self.src_ip {
            writer.write(&v.octets()).unwrap();
        }
        if let IpAddr::V4(v) = self.dst_ip {
            writer.write(&v.octets()).unwrap();
        }
        writer.write(&self.payload).unwrap();
        if let Some(i) = self.options {
            writer.write(i).unwrap();
        }
        if let Some(i) = self.padding {
            writer.write(i).unwrap();
        }
        writer.into_inner()
    }

    fn parse_ipv4<'b>(
        input: &'b [u8],
        input_length: usize,
        version_and_length: u8,
    ) -> IResult<&'b [u8], IPv4<'b>> {
        let header_words = version_and_length & 0x0F;
        let header_length = header_words * 4;
        let additional_length = if header_words > 5 {
            (header_words - 5) * 4
        } else {
            0
        };

        trace!(
            "Input Length={}   Header Length={}   Additional Length={}",
            input_length,
            header_length,
            additional_length
        );

        let (rem, (tos, (raw_length, length))) = do_parse!(
            input,
            tos: be_u8
                >> lengths: map!(be_u16, |s| {
                    let l = s - (header_length as u16);
                    trace!("Payload Length={}", l);
                    (s, l)
                })
                >> ((tos, lengths))
        )?;

        let expected_length = header_length as usize + additional_length as usize + length as usize;
        trace!(
            "Input had length {}B, expected {}B",
            input_length,
            expected_length
        );

        do_parse!(
            rem,
            id: be_u16
                >> flags: be_u16
                >> ttl: be_u8
                >> protocol: map_opt!(be_u8, InternetProtocolId::new)
                >> checksum: be_u16
                >> src_ip: ipv4_address
                >> dst_ip: ipv4_address
                >> payload: map!(take!(length), Payload::Slice)
                >> options: cond!(additional_length > 0, take!(additional_length))
                >> padding:
                    cond!(
                        input_length > expected_length,
                        take!(input_length - expected_length)
                    )
                >> (IPv4 {
                    version_and_length,
                    tos,
                    raw_length,
                    id,
                    flags,
                    ttl,
                    protocol,
                    checksum,
                    src_ip,
                    dst_ip,
                    payload,
                    options,
                    padding,
                })
        )
    }

    pub fn parse<'b>(input: &'b [u8]) -> Result<(&'b [u8], IPv4<'b>), Error> {
        let input_len = input.len();

        be_u8(input).map_err(Error::from).and_then(|r| {
            let (rem, version_and_length) = r;
            let version = version_and_length >> 4;
            if version == 4 {
                IPv4::parse_ipv4(rem, input_len, version_and_length).map_err(Error::from)
            } else {
                Err(Error::Custom { msg: format!("Expected version 4, was {}", version) } )
            }
        })
    }

    pub fn flags(&self) -> Flags {
        Flags::extract_flags(self.flags)
    }
}

pub struct Flags {
    pub do_not_frag: bool,
    pub more_frags: bool,
    pub frag_offset: u16,
}

impl Flags {
    pub fn extract_flags(flags: u16) -> Flags {
        let frag_offset = flags & 8191; // 0001,1111,1111,1111
        let flags = flags >> 13;
        let more_frags = flags & 1 == 1;
        let do_not_frag = flags & 2 == 1;
        Flags {
            do_not_frag,
            more_frags,
            frag_offset
        }
    }

    pub fn is_fragment(&self) -> bool {
        self.more_frags || self.frag_offset != 0
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const RAW_DATA: &'static [u8] = &[
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
    fn parse_ipv4() {
        let _ = env_logger::try_init();

        let (rem, l3) = IPv4::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());
        assert_eq!(
            l3.src_ip,
            "1.2.3.4"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(
            l3.dst_ip,
            "10.11.12.13"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );

        let is_tcp = if let InternetProtocolId::Tcp = l3.protocol {
            true
        } else {
            false
        };

        assert!(is_tcp);

        assert_eq!(l3.as_bytes().as_slice(), RAW_DATA);
    }
}
