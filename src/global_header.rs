use nom::*;

const MAGIC_NUMBER: u32 = 0xA1B2C3D4u32;
#[cfg(target_endian = "little")]
pub const NATIVE_ENDIAN: Endianness = Endianness::Little;
#[cfg(target_endian = "big")]
pub const NATIVE_ENDIAN: Endianness = Endianness::Big;

///
/// Global header associated with libpcap capture files
///
#[allow(unused)]
pub struct GlobalHeader {
    endianness: Endianness,
    version_major: u16,
    version_minor: u16,
    zone: i32,
    sig_figs: i32,
    snap_length: u32,
    network: u32,
}

impl GlobalHeader {
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    pub fn version_major(&self) -> u16 {
        self.version_major
    }

    pub fn version_minor(&self) -> u16 {
        self.version_minor
    }

    pub fn snap_length(&self) -> u32 {
        self.snap_length
    }

    pub fn parse<'a>(input: &'a [u8]) -> IResult<&'a [u8], GlobalHeader> {
        do_parse!(
            input,
            endianness: map!(u32!(NATIVE_ENDIAN), |e| {
                let res = if e == MAGIC_NUMBER {
                    NATIVE_ENDIAN
                } else if NATIVE_ENDIAN == Endianness::Little {
                    Endianness::Big
                } else {
                    Endianness::Little
                };
                #[cfg(feature = "log-errors")]
                debug!("Using endianness {:?} read {:02x} compared to magic number {:02x}, setting endianness to {:?}", NATIVE_ENDIAN, e, MAGIC_NUMBER, res);
                res
            }) >> version_major: u16!(endianness)
                >> version_minor: u16!(endianness)
                >> zone: i32!(endianness)
                >> sig_figs: i32!(endianness)
                >> snap_length: u32!(endianness)
                >> network: u32!(endianness)
                >> (GlobalHeader {
                    endianness: endianness,
                    version_major: version_major,
                    version_minor: version_minor,
                    zone: zone,
                    sig_figs: sig_figs,
                    snap_length: snap_length,
                    network: network
                })
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_endian = "little")]
    const RAW_DATA: &'static [u8] = &[
        0xD4u8, 0xC3u8, 0xB2u8, 0xA1u8, //magic number
        0x04u8, 0x00u8, //version major, 4
        0x02u8, 0x00u8, //version minor, 2
        0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
        0x04u8, 0x00u8, 0x00u8, 0x00u8, //sig figs, 4
        0x13u8, 0x06u8, 0x00u8, 0x00u8, //snap length, 1555
        0x02u8, 0x00u8, 0x00u8, 0x00u8, //network, 2
    ];
    #[cfg(target_endian = "little")]
    const RAW_DATA_REVERSED: &'static [u8] = &[
        0x1Au8, 0x2Bu8, 0x3Cu8, 0x4Du8, //magic number
        0x00u8, 0x04u8, //version major, 4
        0x00u8, 0x02u8, //version minor, 2
        0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
        0x00u8, 0x00u8, 0x00u8, 0x04u8, //sig figs, 4
        0x00u8, 0x00u8, 0x06u8, 0x13u8, //snap length, 1555
        0x00u8, 0x00u8, 0x00u8, 0x02u8, //network, 2
    ];
    #[cfg(target_endian = "big")]
    const RAW_DATA: &'static [u8] = &[
        0x1Au8, 0x2Bu8, 0x3Cu8, 0x4Du8, //magic number
        0x00u8, 0x04u8, //version major, 4
        0x00u8, 0x02u8, //version minor, 2
        0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
        0x00u8, 0x00u8, 0x00u8, 0x04u8, //sig figs, 4
        0x00u8, 0x00u8, 0x06u8, 0x13u8, //snap length, 1555
        0x00u8, 0x00u8, 0x00u8, 0x02u8, //network, 2
    ];
    #[cfg(target_endian = "big")]
    const RAW_DATA_REVERSED: &'static [u8] = &[
        0xD4u8, 0xC3u8, 0xB2u8, 0xA1u8, //magic number
        0x04u8, 0x00u8, //version major, 4
        0x02u8, 0x00u8, //version minor, 2
        0x00u8, 0x00u8, 0x00u8, 0x00u8, //zone, 0
        0x04u8, 0x00u8, 0x00u8, 0x00u8, //sig figs, 4
        0x13u8, 0x06u8, 0x00u8, 0x00u8, //snap length, 1555
        0x02u8, 0x00u8, 0x00u8, 0x00u8, //network, 2
    ];

    #[test]
    fn global_header_native_endian() {
        let _ = env_logger::try_init();

        let (rem, gh) = GlobalHeader::parse(RAW_DATA).expect("Failed to parse header");

        assert!(rem.is_empty());
        assert_eq!(gh.version_major(), 4);
        assert_eq!(gh.version_minor(), 2);
        assert_eq!(gh.endianness(), NATIVE_ENDIAN);
        assert_eq!(gh.snap_length(), 1555);
    }

    #[test]
    fn global_header_not_native_endian() {
        let (rem, gh) = GlobalHeader::parse(RAW_DATA_REVERSED).expect("Failed to parse header");

        let expected_endianness = match NATIVE_ENDIAN {
            Endianness::Little => Endianness::Big,
            Endianness::Big => Endianness::Little,
        };

        assert!(rem.is_empty());
        assert_eq!(gh.version_major(), 4);
        assert_eq!(gh.version_minor(), 2);
        assert_eq!(gh.endianness(), expected_endianness);
        assert_eq!(gh.snap_length(), 1555);
    }
}
