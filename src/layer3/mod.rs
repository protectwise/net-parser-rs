pub mod arp;
pub mod ipv4;
pub mod ipv6;

pub use arp::Arp as Arp;
pub use ipv4::IPv4 as IPv4;
pub use ipv6::IPv6 as IPv6;

use log::*;
use std;

///
/// Available layer 3 representations
///
pub enum Layer3<'a> {
    Arp(Arp),
    IPv4(IPv4<'a>),
    IPv6(IPv6<'a>),
    //Lldp(lldp::Lldp)
}

///
/// IP Protocol numbers https://en.wikipedia.org/wiki/List_of_IP_protocol_numbers
///
#[derive(Clone, Debug, PartialEq, Eq)]
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
