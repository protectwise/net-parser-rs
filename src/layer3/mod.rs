use crate::{
    errors::{
        self,
        Error,
        ErrorKind
    },
    flow::FlowInfo,
    layer4::{
        Layer4FlowInfo,
        Layer4Protocol
    },
    LayerExtraction,
    Protocol
};
use log::*;

pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod lldp;


///
/// Available layer 3 representations
///
pub enum Layer3<'a> {
    Arp(arp::Arp),
    IPv4(ipv4::IPv4<'a>),
    IPv6(ipv6::IPv6<'a>),
    //Lldp(lldp::Lldp)
}

///
/// Layer 2 Protocols
///
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Layer3Protocol {
    IPv4,
    IPv6,
    Arp,
    Lldp,
    Unknown,
}

impl std::fmt::Display for Layer3Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Layer3Protocol::IPv4 => write!(f, "{}", "ipv4"),
            Layer3Protocol::IPv6 => write!(f, "{}", "ipv6"),
            Layer3Protocol::Arp => write!(f, "{}", "arp"),
            Layer3Protocol::Lldp => write!(f, "{}", "lldp"),
            Layer3Protocol::Unknown => write!(f, "{}", "unknown"),
        }
    }
}

impl Protocol for Layer3Protocol {}

///
/// Information from Layer 3 protocols used in stream determination
///
#[derive(Debug)]
pub struct Layer3FlowInfo {
    pub dst_ip: std::net::IpAddr,
    pub src_ip: std::net::IpAddr,
    pub layer4: LayerExtraction<Layer4Protocol, Layer4FlowInfo>,
}

impl FlowInfo for Layer3FlowInfo {
    type P = Layer4Protocol;
    type F = Layer4FlowInfo;

    fn next_layer(&self) -> &LayerExtraction<Self::P, Self::F> {
        &self.layer4
    }
}

///
/// IP Protocol numbers https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
///
#[derive(Clone, Debug, PartialEq)]
pub enum InternetProtocolId {
    AuthenticationHeader,
    HopByHop,
    EncapsulatingSecurityPayload,
    ICMP,
    IPv6Route,
    IPv6Fragment,
    IPv6NoNext,
    IPv6Options,
    Tcp,
    Udp
}

impl InternetProtocolId {
    pub fn new(value: u8) -> Option<InternetProtocolId> {
        match value {
            0 => Some(InternetProtocolId::HopByHop),
            1 => Some(InternetProtocolId::ICMP),
            6 => Some(InternetProtocolId::Tcp),
            17 => Some(InternetProtocolId::Udp),
            43 => Some(InternetProtocolId::IPv6Route),
            44 => Some(InternetProtocolId::IPv6Fragment),
            50 => Some(InternetProtocolId::AuthenticationHeader),
            51 => Some(InternetProtocolId::EncapsulatingSecurityPayload),
            59 => Some(InternetProtocolId::IPv6NoNext),
            60 => Some(InternetProtocolId::IPv6Options),
            _ => {
                //TODO: change to warn once list is more complete
                debug!("Encountered {:02x} when parsing layer 4 id", value);
                None
            }
        }
    }

    pub fn has_next_option(v: InternetProtocolId) -> bool {
        match v {
            InternetProtocolId::AuthenticationHeader => true,
            InternetProtocolId::EncapsulatingSecurityPayload => true,
            InternetProtocolId::HopByHop => true,
            InternetProtocolId::IPv6Route => true,
            InternetProtocolId::IPv6Fragment => true,
            InternetProtocolId::IPv6Options => true,
            _ => false
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate hex_slice;

    use crate::layer3::{ipv4::IPv4, Layer3, Layer3FlowInfo};
    use crate::layer4::Layer4Protocol;
    use crate::LayerExtraction;

    const TCP_RAW_DATA: &'static [u8] = &[
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
        0x01u8, 0x02u8, 0x03u8, 0x04u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0xfcu8, 0xfdu8, 0xfeu8, 0xffu8 //payload, 8 words
    ];

    const BAD_TCP_DATA: &'static [u8] = &[
        // ipv4
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
        0xFFu8, 0x00u8, //header and flags, 0 **length is too large**
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
    fn layer4_trace() {
        let _ = env_logger::try_init();

        let (rem, l3) = IPv4::parse(TCP_RAW_DATA).expect("Unable to parse");

        let layer3 = Layer3FlowInfo::from(l3);

        assert!(layer3.layer4.is_success());
        assert_eq!(*layer3.layer4.protocol(), Layer4Protocol::Tcp);
    }

    #[test]
    fn failing_layer4_trace() {
        let _ = env_logger::try_init();

        let (rem, l3) = IPv4::parse(BAD_TCP_DATA).expect("Unable to parse");

        let layer3= Layer3FlowInfo::from(l3);

        // Layer 4 must fail; the TCP length is too large.
        assert!(layer3.layer4.is_failure());
        assert_eq!(*layer3.layer4.protocol(), Layer4Protocol::Tcp);
    }

}
