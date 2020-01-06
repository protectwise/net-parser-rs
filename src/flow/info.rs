pub mod layer2 {
    use crate::common::{MacAddress, Vlan};

    ///
    /// Representation of layer 2 types that provide information for `Layer2FlowInfo`
    ///
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum Id {
        Ethernet,
    }

    impl Default for Id {
        fn default() -> Self {
            Self::Ethernet
        }
    }

    ///
    /// Information from Layer 2 protocols used in stream determination
    ///
    #[derive(Clone, Copy, Debug, Default)]
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

    impl Default for Id {
        fn default() -> Self {
            Self::IPv4
        }
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

    impl Default for Info {
        fn default() -> Self {
            Self {
                id: Id::default(),
                dst_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
                src_ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            }
        }
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

    impl Default for Id {
        fn default() -> Self {
            Self::Udp
        }
    }

    ///
    /// Information from Layer 3 protocols used in flow determination
    ///
    #[derive(Clone, Copy, Debug, Default)]
    pub struct Info {
        pub id: Id,
        pub dst_port: u16,
        pub src_port: u16
    }
}