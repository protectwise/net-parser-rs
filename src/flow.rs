use super::prelude::*;
use super::record::PcapRecord;

use std;

///
/// Representation of a device on the network, with the mac, ip, and port involved in a connection
///
pub struct Device {
    pub mac: MacAddress,
    pub ip: std::net::IpAddr,
    pub port: u16
}

///
/// Representation of a connection or flow between two devices
///
pub struct Flow {
    pub record: PcapRecord,
    pub source: Device,
    pub destination: Device,
    pub vlan: Vlan
}

impl Flow {
    pub fn source(&self) -> &Device { &self.source }
    pub fn destination(&self) -> &Device { &self.destination }
    pub fn vlan(&self) -> Vlan { self.vlan }
    pub fn record(&self) -> &PcapRecord { &self.record }
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
        self.record.timestamp().duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                std::fmt::Error
            })
            .and_then(|d| {
            write!(f, "Source=[{}]   Destination=[{}]   Vlan={}   Timestamp={}{}",
                   self.source,
                   self.destination,
                   self.vlan,
                   d.as_secs(),
                   d.subsec_millis()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{layer2, layer3, layer4};

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
        let record = PcapRecord::new(
            nom::Endianness::Big,
            std::time::UNIX_EPOCH,
            0,
            0,
            vec![]
        );

        let flow = Flow {
            record: record,
            source: Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)),
                mac: MacAddress([0u8, 1u8, 2u8, 3u8, 4u8, 5u8]),
                port: 80
            },
            destination: Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 99, 98, 97)),
                mac: MacAddress([11u8, 10u8, 9u8, 8u8, 7u8, 6u8]),
                port: 52436
            },
            vlan: 0
        };

        assert_eq!(format!("{}", flow), "Source=[Mac=00:01:02:03:04:05   Ip=0.1.2.3   Port=80]   Destination=[Mac=0b:0a:09:08:07:06   Ip=100.99.98.97   Port=52436]   Vlan=0   Timestamp=00")
    }
}