use crate::Error;
use crate::layer3::InternetProtocolId;

use arrayref::array_ref;
use log::*;
use nom::*;

const ADDRESS_LENGTH: usize = 4;

pub struct IPv4<'a> {
    pub dst_ip: std::net::IpAddr,
    pub src_ip: std::net::IpAddr,
    pub flags: u16,
    pub ttl: u8,
    pub protocol: InternetProtocolId,
    pub payload: &'a [u8],
}

fn to_ip_address(i: &[u8]) -> std::net::IpAddr {
    let ipv4 = std::net::Ipv4Addr::from(array_ref![i, 0, ADDRESS_LENGTH].clone());
    std::net::IpAddr::V4(ipv4)
}

named!(
    ipv4_address<&[u8], std::net::IpAddr>,
    map!(take!(ADDRESS_LENGTH), to_ip_address)
);

impl<'a> IPv4<'a> {
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

        let (rem, (_tos, length)) = do_parse!(
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
            _id: be_u16
                >> flags: be_u16
                >> ttl: be_u8
                >> proto: map_opt!(be_u8, InternetProtocolId::new)
                >> _checksum: be_u16
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
    }
}
