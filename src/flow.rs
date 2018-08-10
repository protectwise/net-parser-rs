use crate::{
    common::{
        MAC_LENGTH,
        MacAddress,
        Vlan
    },
    errors::{
        Error,
        ErrorKind
    },
    layer2::{
        Layer2FlowInfo,
        ethernet::Ethernet
    },
    record::PcapRecord
};

///
/// Representation of a device on the network, with the mac, ip, and port involved in a connection
///
pub struct Device {
    mac: MacAddress,
    ip: std::net::IpAddr,
    port: u16
}

impl Default for Device {
    fn default() -> Self {
        Device {
            mac: MacAddress([0u8; MAC_LENGTH]),
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            port: 0
        }
    }
}

impl Device {
    pub fn mac(&self) -> &MacAddress { &self.mac }
    pub fn ip(&self) -> &std::net::IpAddr { &self.ip }
    pub fn port(&self) -> u16 { self.port }

    pub fn new(
        mac: MacAddress,
        ip: std::net::IpAddr,
        port: u16
    ) -> Device {
        Device {
            mac: mac,
            ip: ip,
            port: port
        }
    }
}

///
/// Trait that provides necessary information to indicate a flow
///
pub trait FlowRecord<'a> {
    fn timestamp(&self) -> &std::time::SystemTime;
    fn actual_length(&self) -> u32;
    fn original_length(&self) -> u32;
    fn payload(&self) -> &'a [u8];
}

///
/// Flow that was built from a record moved
///
pub struct Flow {
    source: Device,
    destination: Device,
    vlan: Vlan
}

impl Flow {
    pub fn source(&self) -> &Device { &self.source }
    pub fn destination(&self) -> &Device { &self.destination }
    pub fn vlan(&self) -> Vlan { self.vlan }

    pub fn new(
        source: Device,
        destination: Device,
        vlan: Vlan
    ) -> Flow {
        Flow {
            source: source,
            destination: destination,
            vlan: vlan
        }
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Mac={}   Ip={}   Port={}",
               self.mac,
               self.ip,
               self.port
        )
    }
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Source=[{}]   Destination=[{}]   Vlan={}",
               self.source,
               self.destination,
               self.vlan
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{
        layer2,
        layer3,
        layer4
    };

    #[test]
    fn format_device() {
        let dev = Device {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)),
            mac: MacAddress([0u8, 1u8, 2u8, 3u8, 4u8, 5u8]),
            port: 80
        };

        assert_eq!(format!("{}", dev), "Mac=00:01:02:03:04:05   Ip=0.1.2.3   Port=80".to_string());
    }

    #[test]
    fn format_flow() {
        let flow = Flow::new(
            Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)),
                mac: MacAddress([0u8, 1u8, 2u8, 3u8, 4u8, 5u8]),
                port: 80
            },
            Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 99, 98, 97)),
                mac: MacAddress([11u8, 10u8, 9u8, 8u8, 7u8, 6u8]),
                port: 52436
            },
            0
        );

        assert_eq!(format!("{}", flow), "Source=[Mac=00:01:02:03:04:05   Ip=0.1.2.3   Port=80]   Destination=[Mac=0b:0a:09:08:07:06   Ip=100.99.98.97   Port=52436]   Vlan=0")
    }
}