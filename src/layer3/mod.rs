pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod lldp;

use log::*;
use std;

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
/// Information from Layer 3 protocols used in stream determination
///
pub struct Layer3FlowInfo {
    pub dst_ip: std::net::IpAddr,
    pub src_ip: std::net::IpAddr,
    pub layer4: crate::layer4::Layer4FlowInfo,
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
    Udp,
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
            _ => false,
        }
    }
}

pub mod errors {
    use crate::layer3::arp;
    use crate::layer3::ipv4;
    use crate::layer3::ipv6;
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "ARP Error")]
        Arp(#[fail(cause)] arp::errors::Error),
        #[fail(display = "IPv4 Error")]
        IPv4(#[fail(cause)] ipv4::errors::Error),
        #[fail(display = "IPv6 Error")]
        IPv6(#[fail(cause)] ipv6::errors::Error)
    }

    impl From<arp::errors::Error> for Error {
        fn from(v: arp::errors::Error) -> Self {
            Error::Arp(v)
        }
    }

    impl From<ipv4::errors::Error> for Error {
        fn from(v: ipv4::errors::Error) -> Self {
            Error::IPv4(v)
        }
    }

    impl From<ipv6::errors::Error> for Error {
        fn from(v: ipv6::errors::Error) -> Self {
            Error::IPv6(v)
        }
    }
}
