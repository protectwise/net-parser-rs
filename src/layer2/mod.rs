pub mod prelude {
    pub use super::super::prelude::*;
    pub use super::super::layer3;
}

pub mod ethernet;

use super::common::*;
use super::layer3::Layer3FlowInfo;

///
/// Layer2 types that can be parsed
///
pub enum Layer2 {
    Ethernet(ethernet::Ethernet)
}

///
/// Information from Layer 2 protocols used in flow determination
///
pub struct Layer2FlowInfo {
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub vlan: Vlan,
    pub layer3: Layer3FlowInfo
}
