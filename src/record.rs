use super::prelude::*;
use super::layer2::{Layer2, ethernet::Ethernet};

use self::nom::*;

use std;

pub struct PcapRecord<'a> {
    endianness: nom::Endianness,
    timestamp: std::time::SystemTime,
    actual_length: u32,
    original_length: u32,
    record: Layer2<'a>
}

impl<'a> PcapRecord<'a> {
    pub fn endianness(&self) -> nom::Endianness { self.endianness }
    pub fn timestamp(&'a self) -> &'a std::time::SystemTime {
        &self.timestamp
    }
    pub fn actual_length(&self) -> u32 {
        self.actual_length
    }
    pub fn original_length(&self) -> u32 {
        self.original_length
    }
    pub fn record(&'a self) -> &'a Layer2<'a> {
        &self.record
    }

    pub fn convert_packet_time(ts_seconds: u32, ts_microseconds: u32) -> std::time::SystemTime {
        let offset = std::time::Duration::from_secs(ts_seconds as u64) + std::time::Duration::from_micros(ts_microseconds as u64);
        std::time::UNIX_EPOCH + offset
    }

    pub(crate) fn parse<'b>(input: &'b [u8], endianness: nom::Endianness) -> nom::IResult<&'b [u8], PcapRecord<'b>> {
        let res = do_parse!(input,

            ts_seconds: u32!(endianness) >>
            ts_microseconds: u32!(endianness) >>
            actual_length: u32!(endianness) >>
            original_length: u32!(endianness) >>

            ( (ts_seconds, ts_microseconds, actual_length, original_length) )
        );

        res.and_then(|r| {
            let (rem, (s, us, l, ol)) = r;

            Ethernet::parse(rem, endianness).map(|l2_res| {
                let (rem_post_l2, l2) = l2_res;
                (rem_post_l2, PcapRecord {
                    endianness: endianness,
                    timestamp: PcapRecord::convert_packet_time(s, us),
                    actual_length: l,
                    original_length: ol,
                    record: Layer2::Ethernet(l2)
                })
            })

        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_convert_timestamp() {
        let ts = PcapRecord::convert_packet_time(1527868899, 152053);

        let offset = std::time::Duration::from_seconds(1527868899).plus_nanos(152053000);
        assert_eq!(ts, std::time::UNIX_EPOCH + offset);
    }
    #[test]
    fn test_parse_record() {
        let data = [
            0x5Bu8, 0x11u8, 0x6Du8, 0xE3u8, //seconds, 1527868899
            0x00u8, 0x02u8, 0x51u8, 0xF5u8, //microseconds, 152053
            0x00u8, 0x00u8, 0x03u8, 0x10u8, //actual length, 784
            0x00u8, 0x00u8, 0x04u8, 0xD0u8, //original length, 1232
            //ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
            0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
            0x00u8, 0x08u8, //payload ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8
        ];

        let record = PcapRecord::parse(data, nom::Endianness::Big).expect("Could not parse");

        let offset = std::time::Duration::from_seconds(1527868899).plus_nanos(152053000);
        assert_eq!(record.timestamp(), std::time::UNIX_EPOCH + offset);
        assert_eq!(record.actual_length(), 54);
        assert_eq!(record.original_length(), 54);

        let is_ethernet = if let Layer2::Ethernet(_) = record.layer2() {
            true
        } else {
            false
        };

        assert!(is_ethernet);
    }
}