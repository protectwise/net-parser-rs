use crate::{
    errors::{
        self,
        Error,
        ErrorKind
    },
    flow::FlowInfo,
    LayerExtraction,
    Protocol
};

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
#[derive(Debug)]
pub struct Layer4FlowInfo {
    pub dst_port: u16,
    pub src_port: u16,
    protocol: Layer4Protocol,
}

impl Layer4FlowInfo {
    pub fn protocol(&self) -> &Layer4Protocol {
        &self.protocol
    }
}


impl FlowInfo for Layer4FlowInfo {
    type P = Layer4Protocol;
    type F = Layer4FlowInfo;

    fn next_layer(&self) -> &LayerExtraction<Self::P, Self::F> {
        &LayerExtraction::None
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Layer4Protocol {
    Tcp,
    Udp,
    Unknown,
}

impl std::fmt::Display for Layer4Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Layer4Protocol::Tcp => write!(f, "{}", "tcp"),
            Layer4Protocol::Udp => write!(f, "{}", "udp"),
            Layer4Protocol::Unknown => write!(f, "{}", "unknown"),
        }
    }
}

impl Protocol for Layer4Protocol {}