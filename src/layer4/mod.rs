pub mod tcp;
pub mod udp;

///
/// Available Layer 4 representations
///
pub enum Layer4<'a> {
    Tcp(tcp::Tcp<'a>),
    Udp(udp::Udp<'a>)
}

///
/// Information from Layer 4 protocols used in stream determination
///
pub struct Layer4FlowInfo {
    pub dst_port: u16,
    pub src_port: u16
}
