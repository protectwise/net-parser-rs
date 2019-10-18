use crate::Error;
use crate::common::{MacAddress, Vlan, MAC_LENGTH};

use arrayref::array_ref;
use byteorder::{BigEndian as BE, WriteBytesExt};
use log::*;
use nom::*;
use std::mem::size_of;
use std::io::{Cursor, Write};

const ETHERNET_PAYLOAD: u16 = 1500u16;

///
/// List of valid ethernet types that aren't payload or vlan. https://en.wikipedia.org/wiki/EtherType
///
#[derive(Clone, Debug, PartialEq)]
pub enum Layer3Id {
    Lldp,
    IPv4,
    IPv6,
    Arp,
}

impl Layer3Id {
    pub fn value(&self) -> u16 {
        match self {
            Layer3Id::Lldp => 0x88ccu16,
            Layer3Id::IPv4 => 0x0800u16,
            Layer3Id::IPv6 => 0x86ddu16,
            Layer3Id::Arp => 0x0806u16,
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum VlanTypeId {
    VlanTagId,
    ProviderBridging,
}

impl VlanTypeId {
    pub fn value(&self) -> u16 {
        match self {
            VlanTypeId::VlanTagId => 0x8100u16,
            VlanTypeId::ProviderBridging => 0x88a8u16
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub enum EthernetTypeId {
    PayloadLength(u16),
    Vlan(VlanTypeId),
    L3(Layer3Id),
}

impl EthernetTypeId {
    fn new(vlan: u16) -> Option<EthernetTypeId> {
        match vlan {
            0x8100u16 => Some(EthernetTypeId::Vlan(VlanTypeId::VlanTagId)),
            0x88a8u16 => Some(EthernetTypeId::Vlan(VlanTypeId::ProviderBridging)),
            0x88ccu16 => Some(EthernetTypeId::L3(Layer3Id::Lldp)),
            0x0800u16 => Some(EthernetTypeId::L3(Layer3Id::IPv4)),
            0x86ddu16 => Some(EthernetTypeId::L3(Layer3Id::IPv6)),
            0x0806u16 => Some(EthernetTypeId::L3(Layer3Id::Arp)),
            x if x <= ETHERNET_PAYLOAD => Some(EthernetTypeId::PayloadLength(x)),
            _ => {
                //TODO: change to warn once list is more complete
                debug!("Encountered {:02x} when parsing Ethernet type", vlan);
                None
            }
        }
    }

    fn value(&self) -> u16 {
        match self {
            EthernetTypeId::PayloadLength(v) => *v,
            EthernetTypeId::Vlan(v) => v.value(),
            EthernetTypeId::L3(v) => v.value(),
        }
    }
}

#[allow(unused)]
pub struct VlanTag {
    pub vlan_type: VlanTypeId,
    pub vlan_value: u16,
    pub prio: u8,
    pub dei: u8,
    pub id: u16,
}

impl VlanTag {
    pub fn vlan(&self) -> u16 {
        self.id
    }
}

pub struct Ethernet<'a> {
    pub dst_mac: MacAddress,
    pub src_mac: MacAddress,
    pub ether_type: EthernetTypeId,
    pub vlans: std::vec::Vec<VlanTag>,
    pub payload: &'a [u8],
}

fn to_mac_address(i: &[u8]) -> MacAddress {
    MacAddress(array_ref![i, 0, MAC_LENGTH].clone())
}

named!(mac_address<&[u8], MacAddress>, map!(take!(MAC_LENGTH), to_mac_address));

impl<'a> Ethernet<'a> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let vlans_size = self.vlans.len() * (size_of::<u16>() * 2);
        let inner = Vec::with_capacity(
            MAC_LENGTH * 2
                + size_of::<u16>()
                + vlans_size
        );
        let mut writer = Cursor::new(inner);
        writer.write(&self.dst_mac.0).unwrap();
        writer.write(&self.src_mac.0).unwrap();
        for vlan in &self.vlans {
            writer.write_u16::<BE>(vlan.vlan_type.value()).unwrap();
            writer.write_u16::<BE>(vlan.vlan_value).unwrap();
        }
        writer.write_u16::<BE>(self.ether_type.value()).unwrap();
        writer.write(self.payload).unwrap();
        writer.into_inner()
    }
    pub fn vlans_to_vlan(vlans: &std::vec::Vec<VlanTag>) -> Vlan {
        let opt_vlan = vlans.first().map(|v| v.vlan());
        opt_vlan.unwrap_or(0)
    }

    pub fn vlan(&self) -> Vlan {
        Ethernet::vlans_to_vlan(&self.vlans)
    }

    fn parse_not_vlan_tag<'b>(
        input: &'b [u8],
        dst_mac: MacAddress,
        src_mac: MacAddress,
        ether_type: EthernetTypeId,
        agg: std::vec::Vec<VlanTag>,
    ) -> nom::IResult<&'b [u8], Ethernet<'b>> {
        do_parse!(
            input,
            payload: rest
                >> (Ethernet {
                    dst_mac: dst_mac,
                    src_mac: src_mac,
                    ether_type: ether_type,
                    vlans: agg,
                    payload: payload.into()
                })
        )
    }

    fn parse_vlan_tag<'b>(
        input: &'b [u8],
        dst_mac: MacAddress,
        src_mac: MacAddress,
        agg: std::vec::Vec<VlanTag>,
    ) -> nom::IResult<&'b [u8], Ethernet<'b>> {
        let (input, vlan) =
            do_parse!(input, vlan: map_opt!(be_u16, EthernetTypeId::new) >> (vlan))?;

        if let EthernetTypeId::Vlan(vlan_type_id) = vlan {
            let (input, (value, prio, dei, id)) = do_parse!(
                input,
                total: be_u16
                    >> ((
                        total,
                        (total & 0x7000) as u8,
                        (total & 0x8000) as u8,
                        total & 0x0FFF
                    ))
            )?;

            let tag = VlanTag {
                vlan_type: vlan_type_id,
                vlan_value: value,
                prio: prio,
                dei: dei,
                id: id,
            };

            debug!("Encountered vlan {:012b}", tag.vlan());

            let mut agg = agg;
            agg.push(tag);

            Ethernet::parse_vlan_tag(input, dst_mac, src_mac, agg)
        } else {
            debug!("Encountered non vlan {:?}", vlan);
            Ethernet::parse_not_vlan_tag(input, dst_mac, src_mac, vlan, agg)
        }
    }

    pub fn parse<'b>(input: &'b [u8]) -> Result<(&'b [u8], Ethernet), Error> {
        trace!("Available={}", input.len());

        let r = do_parse!(
            input,
            dst_mac: mac_address >> src_mac: mac_address >> ((dst_mac, src_mac))
        );

        r.and_then(|res| {
            let (rem, (dst_mac, src_mac)) = res;
            Ethernet::parse_vlan_tag(rem, dst_mac, src_mac, vec![])
        }).map_err(Error::from)
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const PAYLOAD_RAW_DATA: &'static [u8] = &[
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
        0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
        0x00u8, 0x04u8, //payload ethernet
        //payload
        0x01u8, 0x02u8, 0x03u8, 0x04u8,
    ];

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
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0x00u8, 0xfcu8, 0xfdu8, 0xfeu8,
        0xffu8, //payload, 8 words
    ];

    #[test]
    fn parse_ethernet_payload() {
        let _ = env_logger::try_init();

        let (rem, l2) = Ethernet::parse(PAYLOAD_RAW_DATA).expect("Could not parse");

        assert!(rem.is_empty());
        assert_eq!(
            l2.dst_mac.0,
            [0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8]
        );
        assert_eq!(
            l2.src_mac.0,
            [0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8]
        );
        assert!(l2.vlans.is_empty());

        let proto_correct = if let EthernetTypeId::PayloadLength(_) = l2.ether_type {
            true
        } else {
            false
        };

        assert!(proto_correct);
        assert_eq!(l2.as_bytes().as_slice(), PAYLOAD_RAW_DATA);
    }

    #[test]
    fn parse_ethernet_tcp() {
        let _ = env_logger::try_init();

        let (rem, l2) = Ethernet::parse(TCP_RAW_DATA).expect("Could not parse");

        assert!(rem.is_empty());
        assert_eq!(
            l2.dst_mac.0,
            [0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8]
        );
        assert_eq!(
            l2.src_mac.0,
            [0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8]
        );
        assert!(l2.vlans.is_empty());

        let proto_correct = if let EthernetTypeId::L3(Layer3Id::IPv4) = l2.ether_type {
            true
        } else {
            false
        };

        assert!(proto_correct);
        assert_eq!(l2.as_bytes().as_slice(), TCP_RAW_DATA);
    }

    #[test]
    fn test_single_vlan() {
        //TODO
    }

    #[test]
    fn test_multiple_vlans() {
        //TODO
    }
}
