
use nom::*;
use std::num::Wrapping;

#[derive(Copy, Clone, Debug, PartialEq)]
#[repr(u8)]
pub enum IcmpType {
    EchoReply = 0,
    // 1 & 2 are Reserved
    DestinationUnreachable = 3,
    SourceQuench = 4,
    RedirectMessage = 5,
    AlternateHostAddress = 6,
    // 7 is Reserved
    EchoRequest = 8,
    RouterAdvertisement = 9,
    RouterSolicitation = 10,
    TimeExceeded = 11,
    BadIpHeader = 12,
    Timestamp = 13,
    TimestampReply = 14,
    InformationRequest = 15,
    InformationReply = 16,
    AddressMaskRequest = 17,
    AddressMaskReply = 18,
    // 19 - 29 are reserved
    Traceroute = 30,
    DatagramConversionError = 31,
    MobileHostRedirect = 32,
    WhereAreYou = 33,
    HereIAm = 34,
    MobileRegistrationRequest = 35,
    MobileRegistrationReply = 36,
    DomainNameRequest = 37,
    DomainNameReply = 38,
    SkipDiscovery = 39,
    Photuris = 40,
    IcmpExperimentalMobility = 41,
    ExtendedEchoRequest = 42,
    ExtendedEchoReply = 43,
    // 44 - 252 are reserved
    Rfc3692Experiment1 = 253,
    Rfc3692Experiment2 = 254,
    // 255 is reserved
}

impl IcmpType {
    pub fn from(value: u8) -> Option<IcmpType> {
        match value {
            0 => Some(IcmpType::EchoReply),
            3 => Some(IcmpType::DestinationUnreachable),
            4 => Some(IcmpType::SourceQuench),
            5 => Some(IcmpType::RedirectMessage),
            6 => Some(IcmpType::AlternateHostAddress),
            8 => Some(IcmpType::EchoRequest),
            9 => Some(IcmpType::RouterAdvertisement),
            10 => Some(IcmpType::RouterSolicitation),
            11 => Some(IcmpType::TimeExceeded),
            12 => Some(IcmpType::BadIpHeader),
            13 => Some(IcmpType::Timestamp),
            14 => Some(IcmpType::TimestampReply),
            15 => Some(IcmpType::InformationRequest),
            16 => Some(IcmpType::InformationReply),
            17 => Some(IcmpType::AddressMaskRequest),
            18 => Some(IcmpType::AddressMaskReply),
            30 => Some(IcmpType::Traceroute),
            31 => Some(IcmpType::DatagramConversionError),
            32 => Some(IcmpType::MobileHostRedirect),
            33 => Some(IcmpType::WhereAreYou),
            34 => Some(IcmpType::HereIAm),
            35 => Some(IcmpType::MobileRegistrationRequest),
            36 => Some(IcmpType::MobileRegistrationReply),
            37 => Some(IcmpType::DomainNameRequest),
            38 => Some(IcmpType::DomainNameReply),
            39 => Some(IcmpType::SkipDiscovery),
            40 => Some(IcmpType::Photuris),
            41 => Some(IcmpType::IcmpExperimentalMobility),
            42 => Some(IcmpType::ExtendedEchoRequest),
            43 => Some(IcmpType::ExtendedEchoReply),
            253 => Some(IcmpType::Rfc3692Experiment1),
            254 => Some(IcmpType::Rfc3692Experiment2),
            _ => None
        }
    }
}

pub struct Icmp<'a> {
    type_: u8,
    code: u8,
    checksum: u16,
    rest_of_header: u32,
    data: &'a [u8],
}

impl <'a> Icmp<'a> {
    pub fn type_(&self) -> u8 {
        self.type_
    }
    pub fn type_enum(&self) -> Option<IcmpType> {
        IcmpType::from(self.type_)
    }
    pub fn code(&self) -> u8 {
        self.code
    }
    pub fn checksum(&self) -> u16 {
        self.checksum
    }
    pub fn rest_of_header(&self) -> u32 {
        self.rest_of_header
    }
    pub fn data(&self) -> &'a [u8] {
        self.data
    }

    pub fn parse<'b>(input: &'b [u8]) -> IResult<&'b [u8], Icmp<'b>> {
        do_parse!(input,
            type_: be_u8 >>
            code: be_u8 >>
            checksum: be_u16 >>
            header: be_u32 >>
            data: rest >>
            (Icmp {
                type_: type_,
                code: code,
                checksum: checksum,
                rest_of_header: header,
                data: data,
            })
        )
    }

    /// ICMP checksum is the one's complement of the sum of all 16 bit words in the ICMP payload
    /// but with the field for checksum zero'd out
    pub fn compute_checksum(type_: u8, code: u8, rest_of_header: u32, data: &[u8]) -> u16 {
        let sum = ((type_ as u32) << 8 | code as u32) +
            (rest_of_header >> 16) as u32 +
            (rest_of_header & 0xffff) as u32 +
            data.chunks(2).map(|v| {
                match v {
                    [a, b] => ((*a as u32) << 8) | (*b as u32),
                    [a] => ((*a as u32) << 8), // pad right with 0
                    _ => panic!("slice.chunks returned groups of the wrong size, this should not be able to happen")
                }
            }).fold((0u32), |sum, i| sum + i);

        let main = sum & 0xffff;
        let overflow = sum >> 16;

        // overflow to the right side.  Add any remaining high bits to the right side one last time.
        let result = (((main + overflow) & 0xffff) + ((main + overflow) >> 16)) as u16;
        !result
    }

    pub fn calculated_checksum(&self) -> u16 {
        Icmp::compute_checksum(self.type_, self.code, self.rest_of_header, self.data)
    }

    pub fn validate_checksum(&self) -> bool {
        self.checksum == Icmp::compute_checksum(self.type_, self.code, self.rest_of_header, self.data)
    }

}

#[cfg(test)]
mod tests {
    use crate::{
        tests::util::parse_hex_dump,
        layer2::ethernet::Ethernet,
        layer3::ipv4::IPv4,
        layer4::icmp::{
            Icmp,
            IcmpType
        }
    };

    #[test]
    fn checksum() {
        assert_eq!(format!("{:016b}", Icmp::compute_checksum(0, 0, 0, &[])), format!("{:016b}", 0xffffu16));
        assert_eq!(
            format!("{:016b}", Icmp::compute_checksum(8, 0, 0x02002100, &[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69])),
            format!("{:016b}", 0x2a5c)
        );
        assert_eq!(
            format!("{:016b}", Icmp::compute_checksum(0xff, 0xff, 0xffffffff, &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff])),
            format!("{:016b}", 0x00)
        )
    }

    #[test]
    fn parse_icmp() {
        // From https://www.cloudshark.org/captures/fe65ed807bc3
        let bytes = parse_hex_dump(r##"
            # Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
            # Ethernet II, Src: Vmware_34:0b:de (00:0c:29:34:0b:de), Dst: Vmware_e0:14:49 (00:50:56:e0:14:49)
            # Internet Protocol Version 4, Src: 192.168.158.139, Dst: 174.137.42.77
            # Internet Control Message Protocol
            #     Type: 8 (Echo (ping) request)
            #     Code: 0
            #     Checksum: 0x2a5c [correct]
            #     Identifier (BE): 512 (0x0200)
            #     Identifier (LE): 2 (0x0002)
            #     Sequence number (BE): 8448 (0x2100)
            #     Sequence number (LE): 33 (0x0021)
            #     [Response frame: 2]
            #     Data (32 bytes)
            0000   00 50 56 e0 14 49 00 0c 29 34 0b de 08 00 45 00  .PV..I..)4....E.
            0010   00 3c d7 43 00 00 80 01 2b 73 c0 a8 9e 8b ae 89  .<.C....+s......
            0020   2a 4d 08 00 2a 5c 02 00 21 00 61 62 63 64 65 66  *M..*\..!.abcdef
            0030   67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76  ghijklmnopqrstuv
            0040   77 61 62 63 64 65 66 67 68 69                    wabcdefghi
        "##).expect("Invalid packet definition");
        assert_eq!(bytes.len(), 74);

        let enet = Ethernet::parse(bytes.as_slice()).expect("Invalid ethernet").1;
        assert_eq!(format!("{}", enet.dst_mac()), "00:50:56:e0:14:49");

        let ip: IPv4 = IPv4::parse(enet.payload()).expect("Invalid IPv4").1;
        assert_eq!(format!("{}", ip.dst_ip()), "174.137.42.77");

        let icmp: Icmp = Icmp::parse(ip.payload()).expect("Invalid ICMP").1;
        assert_eq!(format!("{:016b}", icmp.checksum()), format!("{:016b}", 0x2a5c));
        assert_eq!(icmp.type_(), 8);
        assert_eq!(icmp.type_enum().expect("Invalid ICMP Type"), IcmpType::EchoRequest);
        assert_eq!(icmp.code(), 0);
        assert_eq!(format!("{:016b}", icmp.rest_of_header()), format!("{:016b}", 0x02002100));
        assert_eq!(format!("{:016b}", icmp.calculated_checksum()), format!("{:016b}", 0x2a5c));
        assert_eq!(icmp.validate_checksum(), true);
        assert_eq!(icmp.data(), &[0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69]);
    }

    #[test]
    fn bad_checksum() {
        let bytes = parse_hex_dump(r##"
            # Frame 1: 74 bytes on wire (592 bits), 74 bytes captured (592 bits)
            # Ethernet II, Src: Vmware_34:0b:de (00:0c:29:34:0b:de), Dst: Vmware_e0:14:49 (00:50:56:e0:14:49)
            # Internet Protocol Version 4, Src: 192.168.158.139, Dst: 174.137.42.77
            # Internet Control Message Protocol
            #     Type: 8 (Echo (ping) request)
            #     Code: 0
            #     Checksum: 0xdead [incorrect, should be 0x2a5c]
            #     Identifier (BE): 512 (0x0200)
            #     Identifier (LE): 2 (0x0002)
            #     Sequence number (BE): 8448 (0x2100)
            #     Sequence number (LE): 33 (0x0021)
            #     [No response seen]
            #     Data (32 bytes)
            0000   00 50 56 e0 14 49 00 0c 29 34 0b de 08 00 45 00  .PV..I..)4....E.
            0010   00 3c d7 43 00 00 80 01 2b 73 c0 a8 9e 8b ae 89  .<.C....+s......
            0020   2a 4d 08 00 de ad 02 00 21 00 61 62 63 64 65 66  *M......!.abcdef
            0030   67 68 69 6a 6b 6c 6d 6e 6f 70 71 72 73 74 75 76  ghijklmnopqrstuv
            0040   77 61 62 63 64 65 66 67 68 69                    wabcdefghi
        "##).expect("Invalid packet definition");
        assert_eq!(bytes.len(), 74);

        let enet = Ethernet::parse(bytes.as_slice()).expect("Invalid ethernet").1;
        assert_eq!(format!("{}", enet.dst_mac()), "00:50:56:e0:14:49");

        let ip: IPv4 = IPv4::parse(enet.payload()).expect("Invalid IPv4").1;
        assert_eq!(format!("{}", ip.dst_ip()), "174.137.42.77");

        let icmp: Icmp = Icmp::parse(ip.payload()).expect("Invalid ICMP").1;
        assert_eq!(format!("{:016b}", icmp.checksum()), format!("{:016b}", 0xDEAD));
        assert_eq!(format!("{:016b}", icmp.calculated_checksum()), format!("{:016b}", 0x2a5c));
        assert_eq!(icmp.validate_checksum(), false);

    }
}