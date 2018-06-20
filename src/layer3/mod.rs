pub mod prelude {
    pub use super::super::prelude::*;
    pub use super::super::layer4;
}

pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod lldp;
pub mod payload;

///
/// Available layer 3 representations
///
pub enum Layer3<'a> {
    //Arp(apr::Arp<'a>),
    IPv4(ipv4::IPv4<'a>),
    //IPv6(ipv6::IPv6<'a>),
    //Lldp(lldp::Lldp<'a>)
    Payload(payload::Payload<'a>),
}