pub mod prelude {
    pub use super::super::prelude::*;
    pub use super::super::layer4;
}

pub mod arp;
pub mod ipv4;
pub mod ipv6;
pub mod lldp;

use std;

///
/// Available layer 3 representations
///
pub enum Layer3 {
    //Arp(apr::Arp),
    IPv4(ipv4::IPv4),
    //IPv6(ipv6::IPv6),
    //Lldp(lldp::Lldp)
}

///
/// Information from Layer 3 protocols used in flow determination
///
pub struct Layer3FlowInfo {
    pub dst_ip: std::net::IpAddr,
    pub src_ip: std::net::IpAddr,
    pub layer4: prelude::layer4::Layer4FlowInfo
}