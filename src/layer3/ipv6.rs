use arrayref::array_ref;
use crate::Error;
use crate::layer3::InternetProtocolId;
use log::*;
use nom::*;
use std;

const ADDRESS_LENGTH: usize = 16;

pub struct IPv6<'a> {
    pub dst_ip: std::net::IpAddr,
    pub src_ip: std::net::IpAddr,
    pub protocol: InternetProtocolId,
    pub payload: &'a [u8],
}

fn to_ip_address(i: &[u8]) -> std::net::IpAddr {
    let ipv6 = std::net::Ipv6Addr::from(array_ref![i, 0, ADDRESS_LENGTH].clone());
    std::net::IpAddr::V6(ipv6)
}

named!(
    ipv6_address<&[u8], std::net::IpAddr>,
    map!(take!(ADDRESS_LENGTH), to_ip_address)
);

impl<'a> IPv6<'a> {
    fn parse_next_header<'b>(
        input: &'b [u8],
        payload_length: u16,
        next_header: InternetProtocolId,
    ) -> IResult<&'b [u8], IPv6<'b>> {
        if InternetProtocolId::has_next_option(next_header.clone()) {
            let (rem, h) = do_parse!(input, h: map_opt!(be_u8, InternetProtocolId::new) >> (h))?;

            IPv6::parse_next_header(rem, payload_length, h)
        } else {
            do_parse!(
                input,
                _h: take!(1) >> //hop limit
                src: ipv6_address >>
                dst: ipv6_address >>
                payload: take!(payload_length) >>

                (
                    IPv6 {
                        dst_ip: dst,
                        src_ip: src,
                        protocol: next_header,
                        payload: payload.into()
                    }
                )
            )
        }
    }

    fn parse_ipv6<'b>(input: &'b [u8]) -> IResult<&'b [u8], IPv6<'b>> {
        let (rem, (payload_length, next_header)) = do_parse!(
            input,
            _f: take!(3) >> //version and stream label
            p: be_u16 >>
            h: map_opt!(be_u8, InternetProtocolId::new) >>

            ( (p, h) )
        )?;

        trace!("Payload Lengt={}", payload_length);

        IPv6::parse_next_header(rem, payload_length, next_header)
    }

    pub fn new(
        dst_ip: std::net::Ipv6Addr,
        src_ip: std::net::Ipv6Addr,
        protocol: InternetProtocolId,
        payload: &'a [u8],
    ) -> IPv6 {
        IPv6 {
            dst_ip: std::net::IpAddr::V6(dst_ip),
            src_ip: std::net::IpAddr::V6(src_ip),
            protocol: protocol,
            payload: payload,
        }
    }

    pub fn parse<'b>(input: &'b [u8]) -> Result<(&'b [u8], IPv6<'b>), Error> {
        trace!("Available={}", input.len());

        be_u8(input).map_err(Error::from).and_then(|r| {
            let (rem, length_check) = r;
            let version = length_check >> 4;
            if version == 6 {
                IPv6::parse_ipv6(rem).map_err(Error::from)
            } else {
                Err(Error::Custom { msg: format!("Expected version 6, version was {}", version) } )
            }
        })
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const RAW_DATA: &'static [u8] = &[
        0x65u8, //version and header length
        0x00u8, 0x00u8, 0x00u8, //traffic class and label
        0x00u8, 0x34u8, //payload length
        0x06u8, //next hop, protocol, tcp
        0x00u8, //hop limit
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8, 0x08u8, 0x09u8, 0x0Au8, 0x0Bu8,
        0x0Cu8, 0x0Du8, 0x0Eu8, 0x0Fu8, 0x0Fu8, //src ip 12:34:56:78:9A:BC:DE:FF
        0x0Fu8, 0x00u8, 0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, 0x07u8, 0x08u8, 0x09u8,
        0x0Au8, 0x0Bu8, 0x0Cu8, 0x0Du8, 0x0Eu8, //dst ip F0:12:34:56:78:9A:BC:DE
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
    fn parse_ipv6() {
        let _ = env_logger::try_init();

        let (rem, l3) = IPv6::parse(RAW_DATA).expect("Unable to parse");

        assert_eq!(
            l3.src_ip,
            "102:304:506:708:90A:B0C:D0E:F0F"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(
            l3.dst_ip,
            "F00:102:304:506:708:90A:B0C:D0E"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );

        let is_tcp = if let InternetProtocolId::Tcp = l3.protocol {
            true
        } else {
            false
        };

        assert!(is_tcp);

        assert!(rem.is_empty());
    }
}
