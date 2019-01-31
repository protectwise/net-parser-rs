use crate::common::{MacAddress, MAC_LENGTH};

use std::net::IpAddr;

///
/// Representation of a device on the network, with the mac, ip, and port involved in a connection
///
#[derive(PartialEq, Eq)]
pub struct Device {
    pub mac: MacAddress,
    pub ip: std::net::IpAddr,
    pub port: u16,
}

impl Default for Device {
    fn default() -> Self {
        Device {
            mac: MacAddress([0u8; MAC_LENGTH]),
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            port: 0,
        }
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Mac={}   Ip={}   Port={}", self.mac, self.ip, self.port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_device() {
        let dev = Device {
            ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)),
            mac: MacAddress([0u8, 1u8, 2u8, 3u8, 4u8, 5u8]),
            port: 80,
        };

        assert_eq!(
            format!("{}", dev),
            "Mac=00:01:02:03:04:05   Ip=0.1.2.3   Port=80".to_string()
        );
    }
}