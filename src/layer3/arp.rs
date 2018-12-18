use crate::{
    common::{MacAddress, MAC_LENGTH},
    layer3::Layer3FlowInfo,
    layer4::{tcp::*, udp::*, Layer4, Layer4FlowInfo},
};

use arrayref::array_ref;
use log::*;
use nom::{Err as NomError, ErrorKind as NomErrorKind, *};

use std::{self, convert::TryFrom};

pub mod errors {
    use crate::nom_error;
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Nom error while parsing ARP")]
        Nom(#[fail(cause)] nom_error::Error),
        #[fail(display = "ARP cannot be converted to a flow")]
        Flow,
    }
}

pub struct Arp {
    sender_ip: std::net::IpAddr,
    sender_mac: MacAddress,
    target_ip: std::net::IpAddr,
    target_mac: MacAddress,
    operation: u16,
}

const ADDRESS_LENGTH: usize = 4;
fn to_ip_address(i: &[u8]) -> std::net::IpAddr {
    let ipv4 = std::net::Ipv4Addr::from(array_ref![i, 0, ADDRESS_LENGTH].clone());
    std::net::IpAddr::V4(ipv4)
}

named!(
    ipv4_address<&[u8], std::net::IpAddr>,
    map!(take!(ADDRESS_LENGTH), to_ip_address)
);

fn to_mac_address(i: &[u8]) -> MacAddress {
    let mac_addr = MacAddress(array_ref![i, 0, MAC_LENGTH].clone());
    mac_addr
}

named!(
    mac_address<MacAddress>,
    map!(take!(MAC_LENGTH), to_mac_address)
);

impl Arp {
    pub fn sender_ip(&self) -> &std::net::IpAddr {
        &self.sender_ip
    }
    pub fn sender_mac(&self) -> &MacAddress {
        &self.sender_mac
    }
    pub fn target_ip(&self) -> &std::net::IpAddr {
        &self.target_ip
    }
    pub fn target_mac(&self) -> &MacAddress {
        &self.target_mac
    }
    pub fn operation(&self) -> &u16 {
        &self.operation
    }

    pub fn new(
        sender_ip: std::net::Ipv4Addr,
        sender_mac: [u8; MAC_LENGTH],
        target_ip: std::net::Ipv4Addr,
        target_mac: [u8; MAC_LENGTH],
        operation: u16,
    ) -> Arp {
        Arp {
            sender_ip: std::net::IpAddr::V4(sender_ip),
            sender_mac: MacAddress(sender_mac),
            target_ip: std::net::IpAddr::V4(target_ip),
            target_mac: MacAddress(target_mac),
            operation,
        }
    }

    pub fn parse(input: &[u8]) -> IResult<&[u8], Arp> {
        do_parse!(
            input,
            hardware_type: be_u16 >>
            protocol_type: be_u16 >>
            hardware_address_length: be_u8 >>
            protocol_address_length: be_u8 >>
            operation: be_u16 >>
            sender_hardware_address: mac_address >> // ethernet address size is 6 bytes
            sender_protocol_address: ipv4_address >> // ipv4 address size is 4
            target_hardware_address: mac_address >>
            target_protocol_address: ipv4_address >>
            (
                Arp {
                    sender_ip: sender_protocol_address,
                    sender_mac: sender_hardware_address,
                    target_ip: target_protocol_address,
                    target_mac: target_hardware_address,
                    operation: operation
                }
            )
        )
    }
}

impl TryFrom<Arp> for Layer3FlowInfo {
    type Error = errors::Error;

    fn try_from(value: Arp) -> Result<Self, Self::Error> {
        Err(errors::Error::Flow)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RAW_DATA: &'static [u8] = &[
        // all the raw datas
        0x00u8, 0x01u8, // hardware type
        0x08u8, 0x00u8, // protocol type
        0x06u8, // hardware address length
        0x04u8, // protocol address length
        0x00u8, 0x01u8, // operation
        0x00u8, 0x0au8, 0xdcu8, 0x64u8, 0x85u8, 0xc2u8, // sender hardware address
        0xc0u8, 0xa8u8, 0x59u8, 0x01u8, // sender protocol address
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, // target hardware address
        0xc0u8, 0xa8u8, 0x59u8, 0x02u8, // target protocol address
    ];

    #[test]
    fn parse_arp() {
        let (rem, l3) = Arp::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());
        assert_eq!(
            *l3.sender_ip(),
            "192.168.89.1"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(
            format!("{}", *l3.sender_mac()),
            "00:0a:dc:64:85:c2".to_string()
        );
        assert_eq!(
            *l3.target_ip(),
            "192.168.89.2"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(
            format!("{}", *l3.target_mac()),
            "00:00:00:00:00:00".to_string()
        );
        assert_eq!(*l3.operation(), 1u16);
    }
}
