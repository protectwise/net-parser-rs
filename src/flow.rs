use super::prelude::*;
use super::record::PcapRecord;
use super::layer2::*;
use super::layer3::*;
use super::layer4::*;

pub struct Device<'a> {
    mac: &'a [u8; MAC_LENGTH],
    ip: &'a std::net::InetAddr,
    port: u16
}

impl<'a> Device<'a> {
    fn mac(&self) -> &'a [u8; MAC_LENGTH] {
        self.mac
    }
    fn ip(&self) -> &'a std::net::InetAddr {
        self.ip
    }
    fn port(&self) -> u16 {
        self.port
    }
}

pub struct FlowInfo<'a> {
    dst: Device<'a>,
    src: Device<'a>,
    vlan: Vlan
}

impl<'a> FlowInfo<'a> {
    fn dst(&self) -> &'a Device<'a> {
        self.dst
    }

    fn src(&self) -> &'a Device<'a> {
        self.src
    }

    fn vlan(&self) -> Vlan {
        self.vlan
    }
}

struct Layer3Info<'a> {
    dst_ip: &'a std::net::InetAddr,
    src_ip: &'a std::net::InetAddr,
    layer4: Layer4Info
}

struct Layer4Info {
    dst_port: u16,
    src_port: u16
}

impl<'a> std::convert::TryFrom<PcapRecord<'a>> for FlowInfo<'a> {
    fn try_layer4(layer4: &Layer4<'a>) -> Result<Layer4Info, errors::Error> {
        match layer4 {
            Layer4::Tcp(ref tcp) => {
                Layer4Info {
                    dst_port: tcp.dst_port(),
                    src_port: tcp.src_port()
                }
            }
        }
    }
    fn try_layer3(layer3: &'a B1) -> Result<Layer3Info<'a>, errors::Error> {

    }
    fn try_from(record: &'a PcapRecord<'a>) -> Result<FlowInfo, errors::Error> {

    }
}