pub mod layer2 {
    use crate::common::{MacAddress, Vlan};

    ///
    /// Representation of layer 2 types that provide information for `Layer2FlowInfo`
    ///
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Id {
        Ethernet,
    }

    ///
    /// Information from Layer 2 protocols used in stream determination
    ///
    #[derive(Clone, Copy, Debug)]
    pub struct Info {
        pub id: Id,
        pub src_mac: MacAddress,
        pub dst_mac: MacAddress,
        pub vlan: Vlan,
    }
}

pub mod layer3 {
    use std::net::IpAddr;

    ///
    /// Representation of Layer3 types that provide information for `Layer3FlowInfo`
    ///
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Id {
        Arp,
        IPv4,
        IPv6,
    }

    ///
    /// Information from Layer 3 protocols used in flow determination
    ///
    #[derive(Clone, Copy, Debug)]
    pub struct Info {
        pub id: Id,
        pub dst_ip: IpAddr,
        pub src_ip: IpAddr,
    }
}

pub mod layer4 {
    ///
    /// Representation of Layer3 types that provide information for `Layer3FlowInfo`
    ///
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Id {
        Tcp,
        Udp,
        Vxlan
    }

    ///
    /// Information from Layer 3 protocols used in flow determination
    ///
    #[derive(Clone, Copy, Debug)]
    pub struct Info {
        pub id: Id,
        pub dst_port: u16,
        pub src_port: u16
    }
}