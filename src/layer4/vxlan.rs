use crate::Error;
use byteorder::{BigEndian as BE, WriteBytesExt};
use nom::*;
use std::mem::size_of;
use std::io::{Cursor, Write};

#[derive(Clone, Copy, Debug)]
pub struct Vxlan<'a> {
    pub flags: u16,
    pub group_policy_id: u16,
    pub raw_network_identifier: u32,
    pub network_identifier: u32, // only can use 3 bytes
    pub payload: &'a [u8],
}

impl<'a> Vxlan<'a> {
    pub fn as_bytes(&self) -> Vec<u8> {
        let inner = Vec::with_capacity(
            size_of::<u16>() * 2
                + size_of::<u32>()
                + self.payload.len()
        );
        let mut writer = Cursor::new(inner);
        writer.write_u16::<BE>(self.flags).unwrap();
        writer.write_u16::<BE>(self.group_policy_id).unwrap();
        writer.write_u32::<BE>(self.raw_network_identifier).unwrap();
        writer.write(self.payload).unwrap();
        writer.into_inner()
    }

    pub fn parse<'b>(input: &'b [u8], endianness: nom::Endianness) -> Result<(&'b [u8], Vxlan<'b>), Error> {
        // TODO: Is Endianness really unknown?
        do_parse!(input,
            flags: u16!(endianness) >>
            group_policy_id: u16!(endianness) >>
            network_identifier: u32!(endianness) >> // actually u24 plus 8 reserved bits.
            //reserved: be_u8 >> // accounted for in bytes captured under network_identifier
            payload: rest >> (
                Vxlan {
                    flags: flags,
                    group_policy_id: group_policy_id,
                    raw_network_identifier: network_identifier,
                    network_identifier: network_identifier>>8,
                    payload: payload
                }
            )
        ).map_err(Error::from)
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        layer2::ethernet::Ethernet,
        layer3::ipv4::IPv4,
        layer4::{
            udp::Udp,
            vxlan::Vxlan,
        },
        tests::util::parse_hex_dump,
    };

    #[test]
    fn encapsulated() {
        // Packet sample came from https://www.cloudshark.org/captures/670aeb7bad79 
        let bytes = parse_hex_dump(r##"
            # Frame 3: 148 bytes on wire (1184 bits), 148 bytes captured (1184 bits) on interface 0
            # Ethernet II, Src: CadmusCo_ae:4d:62 (08:00:27:ae:4d:62), Dst: CadmusCo_f2:1d:8c (08:00:27:f2:1d:8c)
            # Internet Protocol Version 4, Src: 192.168.56.11, Dst: 192.168.56.12
            # User Datagram Protocol, Src Port: 48134 (48134), Dst Port: 4789 (4789)
            # Virtual eXtensible Local Area Network
            # Ethernet II, Src: ba:09:2b:6e:f8:be (ba:09:2b:6e:f8:be), Dst: 4a:7f:01:3b:a2:71 (4a:7f:01:3b:a2:71)
            # Internet Protocol Version 4, Src: 10.0.0.1, Dst: 10.0.0.2
            # Internet Control Message Protocol
            0000   08 00 27 f2 1d 8c 08 00 27 ae 4d 62 08 00 45 00  ..'.....'.Mb..E.
            0010   00 86 d9 99 40 00 40 11 6f 65 c0 a8 38 0b c0 a8  ....@.@.oe..8...
            0020   38 0c bc 06 12 b5 00 72 00 00 08 00 00 00 00 00  8......r........
            0030   7b 00 4a 7f 01 3b a2 71 ba 09 2b 6e f8 be 08 00  {.J..;.q..+n....
            0040   45 00 00 54 2f 4f 40 00 40 01 f7 57 0a 00 00 01  E..T/O@.@..W....
            0050   0a 00 00 02 08 00 4c 8a 0d 3d 00 01 a3 8c 7c 57  ......L..=....|W
            0060   00 00 00 00 b5 80 0a 00 00 00 00 00 10 11 12 13  ................
            0070   14 15 16 17 18 19 1a 1b 1c 1d 1e 1f 20 21 22 23  ............ !"#
            0080   24 25 26 27 28 29 2a 2b 2c 2d 2e 2f 30 31 32 33  $%&'()*+,-./0123
            0090   34 35 36 37                                      4567
        "##).unwrap();
        assert_eq!(bytes.len(), 148);

        let enet = Ethernet::parse(bytes.as_slice()).expect("Invalid ethernet").1;
        assert_eq!(format!("{}", enet.dst_mac), "08:00:27:f2:1d:8c");

        let ip: IPv4 = IPv4::parse(enet.payload).expect("Invalid IPv4").1;
        assert_eq!(format!("{}", ip.dst_ip), "192.168.56.12");

        let udp: Udp = Udp::parse(ip.payload).expect("Invalid udp").1;
        assert_eq!(udp.dst_port, 4789);

        let (remainder, vxlan) = Vxlan::parse(&udp.payload, nom::Endianness::Big).expect("Invalid VXLAN");
        assert_eq!(remainder.len(), 0);
        assert_eq!(vxlan.flags, 0x0800);
        assert_eq!(vxlan.network_identifier, 123);

        assert_eq!(vxlan.as_bytes().as_slice(), udp.payload);

        let enet2 = Ethernet::parse(vxlan.payload).expect("Invalid inner Ethernet").1;
        assert_eq!(format!("{}", enet2.dst_mac), "4a:7f:01:3b:a2:71");

        let ip2: IPv4 = IPv4::parse(enet2.payload).expect("Invalid Inner IPv4").1;
        assert_eq!(format!("{}", ip2.dst_ip), "10.0.0.2");
    }

    #[test]
    fn not_encapsulated() {
        let bytes = parse_hex_dump(r##"
            # Frame 4: 44 bytes on wire (352 bits), 44 bytes captured (352 bits) on interface 1
            # Ethernet II, Src: Apple_b2:43:ff (68:5b:35:b2:43:ff), Dst: 00:86:9c:66:13:11 (00:86:9c:66:13:11)
            # Internet Protocol Version 4, Src: 192.168.0.216, Dst: 1.1.1.1
            # User Datagram Protocol, Src Port: 60406 (60406), Dst Port: 5300 (5300)
            # Data (2 bytes)
            0000   00 86 9c 66 13 11 68 5b 35 b2 43 ff 08 00 45 00  ...f..h[5.C...E.
            0010   00 1e e2 7c 00 00 40 11 00 00 c0 a8 00 d8 01 01  ...|..@.........
            0020   01 01 eb f6 14 b4 00 0a c3 9d 20 0a              .......... .
        "##).unwrap();

        assert_eq!(bytes.len(), 44);

        let enet = Ethernet::parse(bytes.as_slice()).expect("Invalid ethernet").1;
        assert_eq!(format!("{}", enet.dst_mac), "00:86:9c:66:13:11");

        let ip: IPv4 = IPv4::parse(enet.payload).expect("Invalid IPv4").1;
        assert_eq!(format!("{}", ip.dst_ip), "1.1.1.1");

        let udp: Udp = Udp::parse(ip.payload).expect("Invalid udp").1;
        assert_eq!(udp.dst_port, 5300);

        let vxlan = Vxlan::parse(&udp.payload, nom::Endianness::Big);
        assert!(vxlan.is_err(), "Should not parse as VXLan")

    }
}