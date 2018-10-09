use crate::{
    common::*,
    errors::{
        self,
        Error,
        ErrorKind
    },
    flow::FlowInfo,
    layer3::{
        Layer3FlowInfo,
        Layer3Protocol,
    },
    LayerExtraction,
    Protocol,
};

pub mod ethernet;

///
/// Layer2 types that can be parsed
///
pub enum Layer2<'a> {
    Ethernet(ethernet::Ethernet<'a>)
}

///
/// Layer 2 Protocols.
///
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum Layer2Protocol {
    Ethernet
}

impl std::fmt::Display for Layer2Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Layer2Protocol::Ethernet => write!(f, "ethernet"),
        }
    }
}

impl Protocol for Layer2Protocol {}


///
/// Information from Layer 2 protocols used in stream determination
///
#[derive(Debug)]
pub struct Layer2FlowInfo {
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub vlan: Vlan,
    pub layer3: LayerExtraction<Layer3Protocol, Layer3FlowInfo>,
}

impl FlowInfo for Layer2FlowInfo {
    type P = Layer3Protocol;
    type F = Layer3FlowInfo;

    fn next_layer(&self) -> &LayerExtraction<Self::P, Self::F> {
        &self.layer3
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use crate::layer2::ethernet::Ethernet;
    use super::*;

    pub const TCP_RAW_DATA: &'static [u8] = &[
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
        0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
        0x08u8, 0x00u8, //ipv4
        //ipv4
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

    const BAD_IPV4_DATA: &'static [u8] = &[
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
        0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
        0x08u8, 0x00u8, //ipv4
        //ipv4
        0x45u8, //version and header length
        0x00u8, //tos
        0xFFu8, 0x48u8, //length, 20 bytes for header, 52 bytes for ethernet **header length too large**
        0x00u8, 0x00u8, //id
        0x00u8, 0x00u8, //flags
        0x64u8, //ttl
        0x06u8, //protocol, tcp
        0x00u8, 0x00u8, //checksum
        0x01u8, 0x02u8, 0x03u8, 0x04u8, //src ip 1.2.3.4
        0x0Au8, 0x0Bu8, 0x0Cu8, 0x0Du8, //dst ip 10.11.12.13
    ];

    #[test]
    fn layer3_trace() {
        let _ = env_logger::try_init();

        let (rem, l2) = Ethernet::parse(TCP_RAW_DATA).expect("Could not parse");

        assert!(rem.is_empty());

        let layer2 = Layer2FlowInfo::from(l2);

        assert!(layer2.layer3.is_success());
        assert_eq!(*layer2.layer3.protocol(), Layer3Protocol::IPv4);
    }

    #[test]
    fn failing_layer3_trace() {
        let _ = env_logger::try_init();

        let (rem, l2) = Ethernet::parse(BAD_IPV4_DATA).expect("Could not parse");

        assert!(rem.is_empty());

        let layer2 = Layer2FlowInfo::from(l2);

        // Must fail because the header length is too large (0xFF).
        assert!(layer2.layer3.is_failure());
        assert_eq!(*layer2.layer3.protocol(), Layer3Protocol::IPv4);
    }
}