use super::prelude::*;

use self::nom::*;
use self::layer3::{
    Layer3,
    ipv4::IPv4,
    payload::Payload
};

use std;

const ETHERNET_PAYLOAD: u16 = 1500u16;
const VLAN_LENGTH: usize = 4;

#[derive(Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; MAC_LENGTH]);

pub enum Layer3Id {
    Lldp = 0x88cc,
    IPv4 = 0x0800,
    IPv6 = 0x86dd,
    Arp = 0x0806
}

pub enum VlanTypeId {
    VlanTagId = 0x8100,
    ProviderBridging = 0x88a8,
}

pub enum EthernetTypeId {
    PayloadLength(u16),
    Vlan(VlanTypeId),
    L3(Layer3Id)
}

impl EthernetTypeId {
    fn new(vlan: u16) -> Option<EthernetTypeId> {
        match vlan {
            x if x == VlanTypeId::VlanTagId as u16 => Some(EthernetTypeId::Vlan(VlanTypeId::VlanTagId)),
            x if x == VlanTypeId::ProviderBridging as u16 => Some(EthernetTypeId::Vlan(VlanTypeId::ProviderBridging)),
            x if x == Layer3Id::Lldp as u16 => Some(EthernetTypeId::L3(Layer3Id::Lldp)),
            x if x == Layer3Id::IPv4 as u16 => Some(EthernetTypeId::L3(Layer3Id::IPv4)),
            x if x == Layer3Id::IPv6 as u16 => Some(EthernetTypeId::L3(Layer3Id::IPv6)),
            x if x == Layer3Id::Arp as u16 => Some(EthernetTypeId::L3(Layer3Id::Arp)),
            x if x <= ETHERNET_PAYLOAD => Some(EthernetTypeId::PayloadLength(x)),
            x => None
        }
    }
}

pub struct VlanTag {
    vlan_type: VlanTypeId,
    value: [u8; 4]
}

impl VlanTag {
    pub fn vlan(&self) -> u16 {
        unsafe { std::mem::transmute::<[u8; 2], u16>(array_ref!(self.value, 2, 2).clone()) }
    }
}

pub struct Ethernet<'a> {
    dst_mac: MacAddress,
    src_mac: MacAddress,
    ether_type: EthernetTypeId,
    vlans: std::vec::Vec<VlanTag>,
    layer3: Layer3<'a>
}

fn to_mac_address(i: &[u8]) -> MacAddress {
    MacAddress(array_ref![i, 0, MAC_LENGTH].clone())
}

named!(mac_address<&[u8], MacAddress>, map!(take!(MAC_LENGTH), to_mac_address));

impl<'a> Ethernet<'a> {
    pub fn dst_mac(&'a self) -> &'a MacAddress {
        &self.dst_mac
    }

    pub fn src_mac(&'a self) -> &'a MacAddress {
        &self.src_mac
    }

    pub fn vlans(&'a self) -> &'a std::vec::Vec<VlanTag> {
        &self.vlans
    }

    pub fn vlan(&self) -> Vlan {
        let opt_vlan = self.vlans.first().map(|v| v.vlan());
        opt_vlan.unwrap_or(0)
    }

    pub fn layer3(&'a self) -> &'a Layer3<'a> {
        &self.layer3
    }

    fn parse_with_existing_vlan_tag<'b>(
        input: &'b [u8],
        endianness: nom::Endianness,
        dst_mac: MacAddress,
        src_mac: MacAddress,
        vlan_type: VlanTypeId,
        agg: std::vec::Vec<VlanTag>
    ) -> nom::IResult<&'b [u8], Ethernet<'b>> {
        take!(input, VLAN_LENGTH).and_then(|r| {
            let (rem, vlan) = r;
            let mut agg_mut = agg;
            agg_mut.push(VlanTag {
                vlan_type: vlan_type,
                value: array_ref!(vlan, 0, VLAN_LENGTH).clone()
            });
            Ethernet::parse_vlan_tag(rem, endianness, dst_mac, src_mac, agg_mut)
        })
    }

    fn parse_layer_3<'b, P, T, E>(
        input: &'b [u8],
        parser: P,
        endianness: nom::Endianness,
        as_enum: E
    ) -> nom::IResult<&'b [u8], Layer3<'b>>
        where P: FnOnce(&'b [u8], nom::Endianness) -> nom::IResult<&'b [u8], T>,
        E: FnOnce(T) -> Layer3<'b> {
        parser(input, endianness).map(|res| {
            let (rem, layer3) = res;
            ( rem, as_enum(layer3) )
        })
    }

    fn parse_not_vlan<'b>(
        input: &'b [u8],
        endianness: nom::Endianness,
        dst_mac: MacAddress,
        src_mac: MacAddress,
        not_vlan: EthernetTypeId,
        agg: std::vec::Vec<VlanTag>
    ) -> nom::IResult<&'b [u8], Ethernet<'b>> {
        let l3 = match not_vlan {
            EthernetTypeId::L3(ref l3_id) => {
                match l3_id {
//            x if x == EthernetTypeId::Lldp => {
//                Ethernet::parse_layer_3(input, LLdp::parse, endianness, Layer3::Lldp)
//            }
//            x if x == EthernetTypeId::Arp => {
//                Ethernet::parse_layer_3(input, Arp::parse, endianness, Layer3::Arp)
//            }
                    Layer3Id::IPv4 => {
                        Ethernet::parse_layer_3(input, IPv4::parse, endianness, Layer3::IPv4)
                    }
//            x if x == EthernetTypeId::IPv6 => {
//                Ethernet::parse_layer_3(input, IPv6::parse, endianness, Layer3::IPv6)
//            }
                    _ => {
                        Err(Err::convert(Err::Error(error_position!(input, ErrorKind::CondReduce::<u32>))))
                    }
                }
            }
            EthernetTypeId::PayloadLength(length) => {
                Payload::parse(input, endianness, length as usize).map(|r| {
                    let (rem, pl) = r;
                    (rem, Layer3::Payload(pl))
                })
            }
            _ => {
                Err(Err::convert(Err::Error(error_position!(input, ErrorKind::CondReduce::<u32>))))
            }
        };

        l3.map(|r| {
            let (rem, layer3) = r;
            (rem, Ethernet {
                dst_mac: dst_mac,
                src_mac: src_mac,
                ether_type: not_vlan,
                vlans: agg,
                layer3: layer3
            })
        })
    }

    fn parse_vlan_tag<'b>(
        input: &'b [u8],
        endianness: nom::Endianness,
        dst_mac: MacAddress,
        src_mac: MacAddress,
        agg: std::vec::Vec<VlanTag>
    ) -> nom::IResult<&'b [u8], Ethernet<'b>> {
        u16!(input, endianness)
            .and_then(|r| {
                let (rem, vlan) = r;
                match EthernetTypeId::new(vlan) {
                    Some(e) => Ok( (rem, e) ),
                    None => Err(Err::convert(Err::Error(error_position!(rem, ErrorKind::CondReduce::<u32>))))
                }
            })
            .and_then(|r| {
            let (rem, vlan) = r;
            match vlan {
                EthernetTypeId::Vlan(vlan_type_id) => {
                    Ethernet::parse_with_existing_vlan_tag(rem, endianness, dst_mac, src_mac, vlan_type_id, agg)
                }
                not_vlan => {
                    Ethernet::parse_not_vlan(rem, endianness, dst_mac, src_mac, not_vlan, agg)
                }
            }
        })
    }

    pub(crate) fn parse<'b>(input: &'b [u8], endianness: nom::Endianness) -> nom::IResult<&'b [u8], Ethernet<'b>> {
        let r = do_parse!(input,
            dst_mac: mac_address >>
            src_mac: mac_address >>

            ( (dst_mac, src_mac) )
        );

        r.and_then(|res| {
            let (rem, (dst_mac, src_mac)) = res;
            Ethernet::parse_vlan_tag(rem, endianness, dst_mac, src_mac, vec![])
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate hex_slice;
    use self::hex_slice::AsHex;

    use super::*;

    #[test]
    fn parse_ethernet_payload() {
        let _ = env_logger::try_init();

        let data = [
            0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
            0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
            0x00u8, 0x04u8, //payload ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8
        ];

        let (rem, l2) = Ethernet::parse(&data, Endianness::Big).expect("Could not parse");

        assert!(rem.is_empty());
        assert_eq!(l2.dst_mac().0, [0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8]);
        assert_eq!(l2.src_mac().0, [0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8]);
        assert!(l2.vlans().is_empty());

        let proto_correct = if let Layer3::Payload(_) = l2.layer3() {
            true
        } else {
            false
        };

        assert!(proto_correct);
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