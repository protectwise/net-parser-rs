use super::prelude::*;
use super::record::PcapRecord;
use super::layer2::*;
use super::layer3::*;
use super::layer4::*;

use std;

///
/// Representation of a device on the network, with the mac, ip, and port involved in a connection
///
pub struct Device<'a> {
    mac: &'a MacAddress,
    ip: &'a std::net::IpAddr,
    port: u16
}

impl<'a> Device<'a> {
    pub fn mac(&'a self) -> &'a MacAddress {
        &self.mac
    }
    pub fn ip(&'a self) -> &'a std::net::IpAddr {
        &self.ip
    }
    pub fn port(&self) -> u16 {
        self.port
    }
}

///
/// Representation of a connection or flow between two devices
///
pub struct Flow<'a> {
    source: Device<'a>,
    destination: Device<'a>,
    vlan: Vlan,
    timestamp: &'a std::time::SystemTime
}

struct Layer2Info<'a> {
    pub src_mac: &'a MacAddress,
    pub dst_mac: &'a MacAddress,
    pub vlan: Vlan,
    pub layer3: Layer3Info<'a>
}

struct Layer3Info<'a> {
    pub dst_ip: &'a std::net::IpAddr,
    pub src_ip: &'a std::net::IpAddr,
    pub layer4: Layer4Info
}

struct Layer4Info {
    dst_port: u16,
    src_port: u16
}

impl<'a> Flow<'a> {
    pub fn source(&'a self) -> &'a Device<'a> { &self.source }
    pub fn destination(&'a self) -> &'a Device<'a> { &self.destination }
    pub fn vlan(&self) -> Vlan { self.vlan }
    pub fn timestamp(&'a self) -> &'a std::time::SystemTime { &self.timestamp }

    fn try_layer4(layer4: &'a Layer4<'a>) -> Result<Layer4Info, errors::Error> {
        match layer4 {
            Layer4::Tcp(ref tcp) => {
                Ok(
                    Layer4Info {
                        dst_port: tcp.dst_port(),
                        src_port: tcp.src_port()
                    }
                )
            }
            _ => Err(errors::Error::from_kind(errors::ErrorKind::FlowConversion("Invalid layer 4".to_string())))
        }
    }
    fn try_layer3(layer3: &'a Layer3) -> Result<Layer3Info<'a>, errors::Error> {
        match layer3 {
            Layer3::IPv4(ref ipv4) => {
                Flow::try_layer4(ipv4.layer4()).map(|i| {
                    Layer3Info {
                        dst_ip: ipv4.dst_ip(),
                        src_ip: ipv4.src_ip(),
                        layer4: i
                    }
                })
            }
            _ => Err(errors::Error::from_kind(errors::ErrorKind::FlowConversion("Invalid layer 3".to_string())))
        }
    }

    fn try_layer2(layer2: &'a Layer2) -> Result<Layer2Info<'a>, errors::Error> {
        match layer2 {
            Layer2::Ethernet(ref eth) => {
                Flow::try_layer3(eth.layer3()).map(|i| {
                    Layer2Info {
                        src_mac: eth.src_mac(),
                        dst_mac: eth.dst_mac(),
                        vlan: eth.vlan(),
                        layer3: i
                    }
                })
            }
            _ => Err(errors::Error::from_kind(errors::ErrorKind::FlowConversion("Invalid layer 2".to_string())))
        }
    }

    pub fn try_from(record: &'a PcapRecord<'a>) -> Result<Flow<'a>, errors::Error> {
        let l2 = record.layer2();
        Flow::try_layer2(l2).map(move |i| {
            Flow {
                source: Device {
                    mac: i.src_mac,
                    ip: i.layer3.src_ip,
                    port: i.layer3.layer4.src_port
                },
                destination: Device {
                    mac: i.dst_mac,
                    ip: i.layer3.dst_ip,
                    port: i.layer3.layer4.dst_port
                },
                vlan: i.vlan,
                timestamp: record.timestamp()
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::{layer2, layer3, layer4};

    #[test]
    fn extract_flow_from_tcp() {
        let endianness = nom::Endianness::Big;

        let tcp = layer4::tcp::Tcp::new(
            endianness,
            8080,
            5000,
            1,
            2,
            0,
            4,
            &[0u8, 1u8, 2u8, 3u8]
        );

        let ipv4 = layer3::ipv4::IPv4::new(
            endianness,
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(4, 5, 6, 7)),
            0,
            0,
            6,
            Layer4::Tcp(tcp)
        );

        let eth = layer2::ethernet::Ethernet::new(
            endianness,
            MacAddress([0u8; MAC_LENGTH]),
            MacAddress([0u8; MAC_LENGTH]),
            layer2::ethernet::EthernetTypeId::L3(layer2::ethernet::Layer3Id::IPv4),
            vec![],
            Layer3::IPv4(ipv4)
        );

        let record = PcapRecord::new(
            nom::Endianness::Little,
            std::time::UNIX_EPOCH,
            64,
            64,
            Layer2::Ethernet(eth)
        );

        let flow = Flow::try_from(&record).expect("Could not extract flow");

        assert_eq!(flow.source().port(), 5000);
        assert_eq!(*flow.source().ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(4, 5, 6, 7)));
        assert_eq!(flow.source().mac().0, [0u8; MAC_LENGTH]);

        assert_eq!(flow.destination().port(), 8080);
        assert_eq!(*flow.destination().ip(), std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)));
        assert_eq!(flow.destination().mac().0, [0u8; MAC_LENGTH]);

    }
}