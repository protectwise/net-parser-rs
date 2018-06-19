use super::prelude::*;

use self::nom::*;

pub struct Payload<'a> {
    length: usize,
    payload: &'a [u8]
}

impl<'a> Payload<'a> {
    fn length(&self) -> usize {
        self.length
    }
    fn payload(&self) -> &'a [u8] {
        self.payload
    }

    pub(crate) fn parse<'b>(input: &'b [u8], endianness: nom::Endianness, length: usize) -> IResult<&'b [u8], Payload<'b>> {
        do_parse!(input,
            payload: take!(length) >>

            (
                Payload {
                    length: length,
                    payload: payload
                }
            )
        )
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;
    extern crate hex_slice;
    use self::hex_slice::AsHex;

    use super::*;

    #[test]
    fn test_payload() {
        let _ = env_logger::try_init();

        let data = [
            0x01u8, 0x02u8, 0x03u8, 0x04u8
        ];

        let (rem, l3) = Payload::parse(&data, nom::Endianness::Big, 4).expect("Failed to parse");

        assert!(rem.is_empty());

        assert_eq!(l3.length(), 4);
        assert_eq!(l3.payload(), [0x01u8, 0x02u8, 0x03u8, 0x04u8], "Payload Mismatch: {:x}", l3.payload().as_hex());
    }
}