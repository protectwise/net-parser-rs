use crate::{
    errors::{self, Error, ErrorKind},
    layer3::{InternetProtocolId, Layer3FlowInfo},
    layer4::{tcp::*, udp::*, Layer4, Layer4FlowInfo},
};

use arrayref::array_ref;
use log::*;
use nom::{Err as NomError, ErrorKind as NomErrorKind, *};

use std::{self, convert::TryFrom};
use crate::layer4::icmp::Icmp;

const ADDRESS_LENGTH: usize = 4;
const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

pub struct IPv4<'a> {
    dst_ip: std::net::IpAddr,
    src_ip: std::net::IpAddr,
    flags: u16,
    ttl: u8,
    protocol: InternetProtocolId,
    payload: &'a [u8],
}

fn to_ip_address(i: &[u8]) -> std::net::IpAddr {
    let ipv4 = std::net::Ipv4Addr::from(array_ref![i, 0, ADDRESS_LENGTH].clone());
    std::net::IpAddr::V4(ipv4)
}

named!(
    ipv4_address<&[u8], std::net::IpAddr>,
    map!(take!(ADDRESS_LENGTH), to_ip_address)
);

fn is_zero(v: u8) -> bool {
    v == 0u8
}

impl<'a> IPv4<'a> {
    pub fn dst_ip(&self) -> &std::net::IpAddr {
        &self.dst_ip
    }
    pub fn src_ip(&self) -> &std::net::IpAddr {
        &self.src_ip
    }
    pub fn protocol(&self) -> &InternetProtocolId {
        &self.protocol
    }
    pub fn payload(&self) -> &'a [u8] {
        &self.payload
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

        let (rem, (tos, length)) = do_parse!(
            input,
            tos: be_u8
                >> length: map!(be_u16, |s| {
                    let l = s - (header_length as u16);
                    trace!("Payload Length={}", l);
                    l
                })
                >> ((tos, length))
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
                >> proto: map_opt!(be_u8, InternetProtocolId::new)
                >> checksum: be_u16
                >> src_ip: ipv4_address
                >> dst_ip: ipv4_address
                >> payload: take!(length)
                >> _options: cond!(additional_length > 0, take!(additional_length))
                >> _padding:
                    cond!(
                        input_length > expected_length,
                        take!(input_length - expected_length)
                    )
                >> (IPv4 {
                    dst_ip: dst_ip,
                    src_ip: src_ip,
                    flags: flags,
                    ttl: ttl,
                    protocol: proto,
                    payload: payload
                })
        )
    }

    pub fn new(
        dst_ip: std::net::Ipv4Addr,
        src_ip: std::net::Ipv4Addr,
        flags: u16,
        ttl: u8,
        protocol: InternetProtocolId,
        payload: &'a [u8],
    ) -> IPv4 {
        IPv4 {
            dst_ip: std::net::IpAddr::V4(dst_ip),
            src_ip: std::net::IpAddr::V4(src_ip),
            flags: flags,
            ttl: ttl,
            protocol: protocol,
            payload: payload,
        }
    }

    pub fn parse<'b>(input: &'b [u8]) -> IResult<&'b [u8], IPv4<'b>> {
        let input_len = input.len();

        be_u8(input).and_then(|r| {
            let (rem, version_and_length) = r;
            let version = version_and_length >> 4;
            if version == 4 {
                IPv4::parse_ipv4(rem, input_len, version_and_length)
            } else {
                Err(NomError::convert(NomError::Error(error_position!(
                    input,
                    NomErrorKind::CondReduce::<u32>
                ))))
            }
        })
    }
}

impl<'a> TryFrom<IPv4<'a>> for Layer3FlowInfo {
    type Error = errors::Error;

    fn try_from(value: IPv4<'a>) -> Result<Self, Self::Error> {
        debug!("Creating stream info from {:?}", value.protocol);
        let l4 = match value.protocol.clone() {
            InternetProtocolId::Tcp => Tcp::parse(value.payload())
                .map_err(|e| {
                    let err: Self::Error = e.into();
                    err.chain_err(|| errors::Error::from_kind(errors::ErrorKind::FlowParse))
                })
                .and_then(|r| {
                    let (rem, l4) = r;
                    if rem.is_empty() {
                        Layer4FlowInfo::try_from(l4)
                    } else {
                        Err(errors::Error::from_kind(
                            errors::ErrorKind::L3IncompleteParse(rem.len()),
                        ))
                    }
                }),
            InternetProtocolId::Udp => Udp::parse(value.payload())
                .map_err(|e| {
                    let err: Self::Error = e.into();
                    err.chain_err(|| errors::Error::from_kind(errors::ErrorKind::FlowParse))
                })
                .and_then(|r| {
                    let (rem, l4) = r;
                    if rem.is_empty() {
                        Layer4FlowInfo::try_from(l4)
                    } else {
                        Err(errors::Error::from_kind(
                            errors::ErrorKind::L3IncompleteParse(rem.len()),
                        ))
                    }
                }),
            InternetProtocolId::ICMP => Icmp::parse(value.payload)
                .map_err(|e| {
                    let err: Self::Error = e.into();
                    err.chain_err(|| errors::Error::from_kind(errors::ErrorKind::FlowParse))
                })
                .and_then(|r| {
                    let (rem, l4) = r;
                    if rem.is_empty() {
                        Layer4FlowInfo::try_from(l4)
                    } else {
                        Err(errors::Error::from_kind(
                            errors::ErrorKind::L3IncompleteParse(rem.len()),
                        ))
                    }
                }),
            _ => Err(errors::Error::from_kind(errors::ErrorKind::IPv4Type(
                value.protocol,
            ))),
        }?;

        Ok(Layer3FlowInfo {
            src_ip: value.src_ip,
            dst_ip: value.dst_ip,
            layer4: l4,
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate hex_slice;
    use self::hex_slice::AsHex;

    use super::*;
    use crate::tests::util::parse_hex_dump;
    use crate::layer2::ethernet::Ethernet;

    const RAW_DATA: &'static [u8] = &[
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
            *l3.src_ip(),
            "1.2.3.4"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(
            *l3.dst_ip(),
            "10.11.12.13"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );

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

        assert_eq!(
            info.src_ip,
            "1.2.3.4"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(
            info.dst_ip,
            "10.11.12.13"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(info.layer4.src_port, 50871);
        assert_eq!(info.layer4.dst_port, 80);
    }

    #[test]
    fn convert_ipv4_icmp() {
        let _ = env_logger::try_init();

        // From https://www.cloudshark.org/captures/fe65ed807bc3
        let bytes = parse_hex_dump(r##"
            # Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
            # Ethernet II, Src: Vmware_34:0b:de (00:0c:29:34:0b:de), Dst: Vmware_e0:14:49 (00:50:56:e0:14:49)
            # Internet Protocol Version 4, Src: 192.168.158.139, Dst: 174.137.42.77
            # Internet Control Message Protocol
            #     Type: 8 (Echo (ping) request)
            #     Code: 0
            #     Checksum: 0x2a5c [correct]
            #     Identifier (BE): 512 (0x0200)
            #     Identifier (LE): 2 (0x0002)
            #     Sequence number (BE): 8448 (0x2100)
            #     Sequence number (LE): 33 (0x0021)
            #     [Response frame: 2]
            #     Data (32 bytes)
            0000   00 50 56 e0 14 49 00 0c 29 34 0b de 08 00 45 00  .PV..I..)4....E.
            0010   00 3c d7 43 00 00 80 01 2b 73 c0 a8 9e 8b ae 89  .<.C....+s......
            0020   2a 4d 08 00 2a 5c 02 00 21 00 61 62 63 64 65 66  *M..*\..!.abcdef
            0030   67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76  ghijklmnopqrstuv
            0040   77 61 62 63 64 65 66 67 68 69                    wabcdefghi
        "##).expect("Invalid packet definition");

        assert_eq!(bytes.len(), 74);

        let enet = Ethernet::parse(bytes.as_slice()).expect("Invalid ethernet").1;
        assert_eq!(format!("{}", enet.dst_mac()), "00:50:56:e0:14:49");

        let (rem, l3) = IPv4::parse(enet.payload()).expect("Unable to parse");

        let info = Layer3FlowInfo::try_from(l3).expect("Could not convert to layer 3 info");

        // ICMP does not have ports, so from a flow perspective we treat them as zero (0)
        assert_eq!(info.layer4.src_port, 0);
        assert_eq!(info.layer4.dst_port, 0);
    }
}
