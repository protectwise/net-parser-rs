use super::prelude::*;

use self::nom::*;
use self::layer4::{Layer4, tcp::Tcp, udp::Udp};
use std;

const ADDRESS_LENGTH: usize = 4;
const HEADER_LENGTH: usize = 4 * std::mem::size_of::<u16>();

struct IPv4Info {
    endianness: nom::Endianness,
    dst_ip: std::net::IpAddr,
    src_ip: std::net::IpAddr,
    flags: u16,
    ttl: u8,
    protocol: u8
}

pub struct IPv4<'a> {
    info: IPv4Info,
    layer4: Layer4<'a>
}

fn to_ip_address(i: &[u8]) -> std::net::IpAddr {
    let ipv4 = std::net::Ipv4Addr::from(array_ref![i, 0, ADDRESS_LENGTH].clone());
    std::net::IpAddr::V4(ipv4)
}

named!(
    ip_address<&[u8], std::net::IpAddr>,
    map!(take!(ADDRESS_LENGTH), to_ip_address)
);

impl<'a> IPv4<'a> {
    pub fn dst_ip(&self) -> &std::net::IpAddr {
        &self.info.dst_ip
    }
    pub fn src_ip(&self) -> &std::net::IpAddr {
        &self.info.src_ip
    }
    pub fn layer4(&self) -> &Layer4<'a> {
        &self.layer4
    }

    pub(crate) fn parse_protocol<'b>(
        input: &'b [u8],
        endianness: nom::Endianness,
        protocol: u8
    ) -> IResult<&'b [u8], Layer4<'b>> {
        match protocol {
            6 => Tcp::parse(input, endianness).map(|l| {
                (l.0, Layer4::Tcp(l.1))
            }),
            17 => Udp::parse(input, endianness).map(|l| {
                (l.0, Layer4::Udp(l.1))
            }),
            _ => Err(Err::convert(Err::Error(error_position!(input, ErrorKind::CondReduce::<u32>))))
        }
    }

    pub(crate) fn parse_ipv4<'b>(input: &'b [u8], endianness: nom::Endianness, length_check: u8) -> IResult<&'b [u8], IPv4<'b>> {
        let header_length = (length_check  & 0x0F) * 4;

        let info_res = do_parse!(input,
            tos: be_u8 >>
            length: u16!(endianness) >>
            id: u16!(endianness) >>
            flags: u16!(endianness) >>
            ttl: be_u8 >>
            proto: be_u8 >>
            checksum: u16!(endianness) >>
            src_ip: ip_address >>
            dst_ip: ip_address >>
            payload: take!(length) >>

            (

                (IPv4Info {
                    endianness: endianness,
                    dst_ip: dst_ip,
                    src_ip: src_ip,
                    flags: flags,
                    ttl: ttl,
                    protocol: proto
                }, payload)
            )
        );

        info_res
            .and_then(|t| {
            let (rem, (info, payload)) = t;
            IPv4::parse_protocol(payload, endianness, info.protocol).map(|r| {
                (rem, IPv4 {
                    info: info,
                    layer4: r.1
                })
            })
        })
    }

    pub(crate) fn parse<'b>(input: &'b [u8], endianness: nom::Endianness) -> IResult<&'b [u8], IPv4<'b>> {
        be_u8(input).and_then(|r| {
            let (rem, length_check) = r;
            let length = length_check >> 4;
            if length == 4 {
                IPv4::parse_ipv4(rem, endianness, length_check)
            } else {
                Err(Err::convert(Err::Error(error_position!(rem, ErrorKind::CondReduce::<u32>))))
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ipv4() {

        let raw = [
            0x45u8, //version and header length
            0x00u8, //tos
            0x00u8, 0x64u8, //length
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
            0xfcu8, 0xfdu8, 0xfeu8, 0xffu8 //payload, 8 words
        ];

        let l3 = IPv4::parse(raw, Endianness::Big).expect("Unable to parse");

        assert_eq!(l3.dst_ip, "1.2.3.4".parse().expect("Could not parse ip address"));
        assert_eq!(l3.src_ip, "10.11.12.13".parse().expect("Could not parse ip address"));

        let is_tcp = if let Layer4::Tcp(_) = l3.layer4() {
            true
        } else {
            false
        };

        assert!(is_tcp);
    }
}