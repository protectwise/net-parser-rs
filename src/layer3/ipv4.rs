use super::prelude::*;
use super::{InternetProtocolId, Layer3FlowInfo};

use self::nom::*;
use self::layer4::{
    Layer4,
    Layer4FlowInfo,
    tcp::*,
    udp::*};
use std;
use std::convert::TryFrom;

const ADDRESS_LENGTH: usize = 4;
const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

pub struct IPv4 {
    dst_ip: std::net::IpAddr,
    src_ip: std::net::IpAddr,
    flags: u16,
    ttl: u8,
    protocol: InternetProtocolId,
    payload: std::vec::Vec<u8>
}

fn to_ip_address(i: &[u8]) -> std::net::IpAddr {
    let ipv4 = std::net::Ipv4Addr::from(array_ref![i, 0, ADDRESS_LENGTH].clone());
    std::net::IpAddr::V4(ipv4)
}

named!(
    ipv4_address<&[u8], std::net::IpAddr>,
    map!(take!(ADDRESS_LENGTH), to_ip_address)
);

impl IPv4 {
    pub fn dst_ip(&self) -> &std::net::IpAddr {
        &self.dst_ip
    }
    pub fn src_ip(&self) -> &std::net::IpAddr {
        &self.src_ip
    }
    pub fn protocol(&self) -> &InternetProtocolId {
        &self.protocol
    }
    pub fn payload(&self) -> &std::vec::Vec<u8> { &self.payload }

    fn parse_ipv4(input: &[u8], length_check: u8) -> IResult<&[u8], IPv4> {
        let header_length = (length_check  & 0x0F) * 4;

        do_parse!(input,

            tos: be_u8 >>
            length: map!(be_u16, |s| {
                s - (header_length as u16)
            }) >>
            id: be_u16 >>
            flags: be_u16 >>
            ttl: be_u8 >>
            proto: map_opt!(be_u8, InternetProtocolId::new) >>
            checksum: be_u16 >>
            src_ip: ipv4_address >>
            dst_ip: ipv4_address >>
            payload: take!(length) >>

            (
                IPv4 {
                    dst_ip: dst_ip,
                    src_ip: src_ip,
                    flags: flags,
                    ttl: ttl,
                    protocol: proto,
                    payload: payload.into()
                }
            )
        )
    }

    pub fn new(
        dst_ip: std::net::Ipv4Addr,
        src_ip: std::net::Ipv4Addr,
        flags: u16,
        ttl: u8,
        protocol: InternetProtocolId,
        payload: std::vec::Vec<u8>
    ) -> IPv4 {
        IPv4 {
            dst_ip: std::net::IpAddr::V4(dst_ip),
            src_ip: std::net::IpAddr::V4(src_ip),
            flags: flags,
            ttl: ttl,
            protocol: protocol,
            payload: payload
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], IPv4> {
        be_u8(input).and_then(|r| {
            let (rem, length_check) = r;
            let length = length_check >> 4;
            if length == 4 {
                IPv4::parse_ipv4(rem, length_check)
            } else {
                Err(Err::convert(Err::Error(error_position!(rem, ErrorKind::CondReduce::<u32>))))
            }
        })
    }
}

impl TryFrom<IPv4> for Layer3FlowInfo {
    type Error = errors::Error;

    fn try_from(value: IPv4) -> Result<Self, Self::Error> {
        debug!("Creating flow info from {:?}", value.protocol);
        let l4 = match value.protocol.clone() {
            InternetProtocolId::Tcp => {
                layer4::tcp::Tcp::parse(value.payload())
                    .map_err(|e| {
                        let err: Self::Error = e.into();
                        err.chain_err(|| errors::Error::from_kind(errors::ErrorKind::FlowParse))
                    }).and_then(|r| {
                    let (rem, l4) = r;
                    if rem.is_empty() {
                        Layer4FlowInfo::try_from(l4)
                    } else {
                        Err(errors::Error::from_kind(errors::ErrorKind::IncompleteParse(rem.len())))
                    }
                })
            }
            InternetProtocolId::Udp => {
                layer4::udp::Udp::parse(value.payload())
                    .map_err(|e| {
                        let err: Self::Error = e.into();
                        err.chain_err(|| errors::Error::from_kind(errors::ErrorKind::FlowParse))
                    }).and_then(|r| {
                    let (rem, l4) = r;
                    if rem.is_empty() {
                        Layer4FlowInfo::try_from(l4)
                    } else {
                        Err(errors::Error::from_kind(errors::ErrorKind::IncompleteParse(rem.len())))
                    }
                })
            }
            _ => {
                Err(errors::Error::from_kind(errors::ErrorKind::IPv4Type(value.protocol)))
            }
        }?;

        Ok(Layer3FlowInfo {
            src_ip: value.src_ip,
            dst_ip: value.dst_ip,
            layer4: l4
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
        0x45u8, //version and header length
        0x00u8, //tos
        0x00u8, 0x43u8, //length, 20 bytes for header, 45 bytes for ethernet
        0x00u8, 0x00u8, //id
        0x00u8, 0x00u8, //flags
        0x64u8, //ttl
        0x06u8, //protocol, tcp
        0x00u8, 0x00u8, //checksum
        0x01u8, 0x02u8, 0x03u8, 0x04u8, //src ip 1.2.3.4
        0x0Au8, 0x0Bu8, 0x0Cu8, 0x0Du8, //dst ip 10.11.12.13
        //tcp
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
        0xfcu8, 0xfdu8, 0xfeu8, 0xffu8 //payload, 8 words (32 bytes)
    ];

    #[test]
    fn parse_ipv4() {
        let _ = env_logger::try_init();

        let (rem, l3) = IPv4::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());
        assert_eq!(*l3.src_ip(), "1.2.3.4".parse::<std::net::IpAddr>().expect("Could not parse ip address"));
        assert_eq!(*l3.dst_ip(), "10.11.12.13".parse::<std::net::IpAddr>().expect("Could not parse ip address"));

        let is_tcp = if let InternetProtocolId::Tcp = l3.protocol() {
            true
        } else {
            false
        };

        assert!(is_tcp);
    }
    #[test]
    fn convert_ipv4() {
        let _ = env_logger::try_init();

        let (rem, l3) = IPv4::parse(RAW_DATA).expect("Unable to parse");

        let info = Layer3FlowInfo::try_from(l3).expect("Could not convert to layer 3 info");

        assert_eq!(info.src_ip, "1.2.3.4".parse::<std::net::IpAddr>().expect("Could not parse ip address"));
        assert_eq!(info.dst_ip, "10.11.12.13".parse::<std::net::IpAddr>().expect("Could not parse ip address"));
        assert_eq!(info.layer4.src_port, 50871);
        assert_eq!(info.layer4.dst_port, 80);
    }
}