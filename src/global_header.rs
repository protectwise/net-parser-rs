use super::prelude::*;

use self::nom::*;

const MAGIC_NUMBER: u32 = 0xa1b2c3d4u32;

pub struct GlobalHeader {
    endianness: Endianness,
    version_major: u16,
    version_minor: u16,
    zone: i32,
    sig_figs: i32,
    snap_length: u32,
    network: u32
}

impl GlobalHeader {
    pub fn endianness(&self) -> Endianness { self.endianness }

    pub fn snap_length(&self) -> u32 {
        self.snap_length
    }

    pub(crate) fn parse<'a>(input: &'a [u8]) -> IResult<&'a [u8], GlobalHeader> {
        do_parse!(input,

            endianness: map!(be_u32, |e| {
                match e {
                    MAGIC_NUMBER => Endianness::Big,
                    _ => Endianness::Little
                }
            }) >>
            version_major: u16!(endianness) >>
            version_minor: u16!(endianness) >>
            zone: i32!(endianness) >>
            sig_figs: i32!(endianness) >>
            snap_length: u32!(endianness) >>
            network: u32!(endianness) >>

            (
                GlobalHeader {
                    endianness: endianness,
                    version_major: version_major,
                    version_minor: version_minor,
                    zone: zone,
                    sig_figs: sig_figs,
                    snap_length: snap_length,
                    network: network
                }
            )
    )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_global_header_big_endian() {
        let raw = [
            0xa1u8, 0xb2, 0xc3, 0xd4u8, //magic number
            0x04u8, //version major, 4
            0x02u8, //version minor, 2
            0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
            0x00u8, 0x00u8, 0x00u8, 0x04u8, //sig figs, 4
            0x00u8, 0x00u8, 0x06u8, 0x13u8, //snap length, 1555
            0x00u8, 0x00u8, 0x00u8, 0x02u8, //network, 2
        ];

        let (rem, gh) = GlobalHeader::parse(raw).expect("Failed to parse header");

        assert!(rem.is_empty());
        assert_eq!(gh.endianness(), Endianness::Big)
    }
    #[test]
    fn test_global_header_little_endian() {
        let raw = [
            0xa1u8, 0xb2, 0xc3, 0xd4u8, //magic number
            0x04u8, //version major, 4
            0x02u8, //version minor, 2
            0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
            0x00u8, 0x00u8, 0x00u8, 0x04u8, //sig figs, 4
            0x00u8, 0x00u8, 0x06u8, 0x13u8, //snap length, 1555
            0x00u8, 0x00u8, 0x00u8, 0x02u8, //network, 2
        ].to_le();

        let (rem, gh) = GlobalHeader::parse(raw).expect("Failed to parse header");

        assert!(rem.is_empty());
        assert_eq!(gh.endianness(), Endianness::Little)
    }
}