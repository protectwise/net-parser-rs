use crate::{
    common::*,
    layer3::Layer3FlowInfo
};

pub mod ethernet;

///
/// Layer2 types that can be parsed
///
pub enum Layer2<'a> {
    Ethernet(ethernet::Ethernet<'a>)
}

///
/// Information from Layer 2 protocols used in stream determination
///
pub struct Layer2FlowInfo {
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub vlan: Vlan,
    pub layer3: Layer3FlowInfo
}
