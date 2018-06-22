pub mod prelude {
    pub use super::super::prelude::*;
}

pub mod tcp;
pub mod udp;

///
/// Available Layer 4 representations
///
pub enum Layer4 {
    Tcp(tcp::Tcp),
    Udp(udp::Udp)
}

///
/// Information from Layer 4 protocols used in flow determination
///
pub struct Layer4FlowInfo {
    pub dst_port: u16,
    pub src_port: u16
}
