use log::*;

use crate::{
    common::{MacAddress, Vlan, MAC_LENGTH},
    errors::Error,
    layer2::{ethernet::Ethernet, Layer2FlowInfo},
    parse::record::PcapRecord,
};

use std::{self, convert::TryFrom};

///
/// Representation of a device on the network, with the mac, ip, and port involved in a connection
///
#[derive(PartialEq, Eq)]
pub struct Device {
    mac: MacAddress,
    ip: std::net::IpAddr,
    port: u16,
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

impl Device {
    pub fn mac(&self) -> &MacAddress {
        &self.mac
    }
    pub fn ip(&self) -> &std::net::IpAddr {
        &self.ip
    }
    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn new(mac: MacAddress, ip: std::net::IpAddr, port: u16) -> Device {
        Device {
            mac: mac,
            ip: ip,
            port: port,
        }
    }
}

///
/// Trait that provides necessary information to indicate a flow
///
pub trait FlowExtraction {
    fn payload(&self) -> &[u8];

    fn extract_flow(&self) -> Result<Flow, Error> {
        trace!("Creating stream from payload of {}B", self.payload().len());

        let payload_ref = self.payload();

        let l2 = Ethernet::parse(payload_ref)
            .map_err(|ref e| {
                #[cfg(feature = "log-errors")]
                error!("Error parsing ethernet {:?}", e);
                let l2_error = crate::layer2::ethernet::errors::Error::Nom(e.into());
                Error::L2(l2_error.into())
            })
            .and_then(|r| {
                let (rem, l2) = r;
                if rem.is_empty() {
                    Layer2FlowInfo::try_from(l2).map_err(|e| Error::L2(e.into()))
                } else {
                    Err(Error::Incomplete { size: rem.len() })
                }
            })?;

        let flow = Flow::new(
            Device::new(l2.src_mac, l2.layer3.src_ip, l2.layer3.layer4.src_port),
            Device::new(l2.dst_mac, l2.layer3.dst_ip, l2.layer3.layer4.dst_port),
            l2.vlan,
        );

        Ok(flow)
    }
}

///
/// Flow that was built from a record moved
///
#[derive(PartialEq, Eq)]
pub struct Flow {
    source: Device,
    destination: Device,
    vlan: Vlan,
}

impl Flow {
    pub fn source(&self) -> &Device {
        &self.source
    }
    pub fn destination(&self) -> &Device {
        &self.destination
    }
    pub fn vlan(&self) -> Vlan {
        self.vlan
    }

    pub fn new(source: Device, destination: Device, vlan: Vlan) -> Flow {
        Flow {
            source: source,
            destination: destination,
            vlan: vlan,
        }
    }
}

impl std::fmt::Display for Device {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "Mac={}   Ip={}   Port={}", self.mac, self.ip, self.port)
    }
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Source=[{}]   Destination=[{}]   Vlan={}",
            self.source, self.destination, self.vlan
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::{layer2, layer3, layer4};
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

    #[test]
    fn format_flow() {
        let flow = Flow::new(
            Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)),
                mac: MacAddress([0u8, 1u8, 2u8, 3u8, 4u8, 5u8]),
                port: 80,
            },
            Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 99, 98, 97)),
                mac: MacAddress([11u8, 10u8, 9u8, 8u8, 7u8, 6u8]),
                port: 52436,
            },
            0,
        );

        assert_eq!(format!("{}", flow), "Source=[Mac=00:01:02:03:04:05   Ip=0.1.2.3   Port=80]   Destination=[Mac=0b:0a:09:08:07:06   Ip=100.99.98.97   Port=52436]   Vlan=0")
    }
}
