use super::prelude::*;
use super::layer2::{Layer2, ethernet::Ethernet};

use self::nom::*;

use std;

///
/// Pcap record associated with a libpcap capture
///
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
    pub fn layer2(&'a self) -> &'a Layer2<'a> {
        &self.record
    }

    pub fn convert_packet_time(ts_seconds: u32, ts_microseconds: u32) -> std::time::SystemTime {
        let offset = std::time::Duration::from_secs(ts_seconds as u64) + std::time::Duration::from_micros(ts_microseconds as u64);
        std::time::UNIX_EPOCH + offset
    }

    pub fn new<'b>(
        endianness: nom::Endianness,
        timestamp: std::time::SystemTime,
        actual_length: u32,
        original_length: u32,
        record: Layer2<'b>
    ) -> PcapRecord<'b> {
        PcapRecord {
            endianness,
            timestamp,
            actual_length,
            original_length,
            record
        }
    }

    pub fn parse<'b>(input: &'b [u8], endianness: nom::Endianness) -> nom::IResult<&'b [u8], PcapRecord<'b>> {
        let res = do_parse!(input,

            ts_seconds: u32!(endianness) >>
            ts_microseconds: u32!(endianness) >>
            actual_length: u32!(endianness) >>
            original_length: u32!(endianness) >>
            payload: take!(actual_length) >>

            ( (ts_seconds, ts_microseconds, actual_length, original_length, payload) )
        );

        res.and_then(|r| {
            let (rem, (s, us, l, ol, pl)) = r;

            Ethernet::parse(pl, endianness).map(|l2_res| {
                let (_, l2) = l2_res;
                (rem, PcapRecord {
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

impl<'a> std::fmt::Display for PcapRecord<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.timestamp.duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| {
                std::fmt::Error
            })
            .and_then(|d| {
                write!(f, "Timestamp={}{}   Length={}   Original Length={}",
                       d.as_secs(),
                       d.subsec_millis(),
                       self.actual_length,
                       self.original_length
                )
            })
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;

    #[test]
    fn display_record() {
        let _ = env_logger::try_init();

        let data = [
            0x5Bu8, 0x11u8, 0x6Du8, 0xE3u8, //seconds, 1527868899
            0x00u8, 0x02u8, 0x51u8, 0xF5u8, //microseconds, 152053
            0x00u8, 0x00u8, 0x00u8, 0x12u8, //actual length, 18
            0x00u8, 0x00u8, 0x04u8, 0xD0u8, //original length, 1232
            //ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
            0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
            0x00u8, 0x04u8, //payload ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8
        ];

        let record = PcapRecord::parse(&data, nom::Endianness::Big).expect("Could not parse").1;

        assert_eq!(format!("{}", record), "Timestamp=1527868899152   Length=18   Original Length=1232");
    }

    #[test]
    fn convert_timestamp() {
        let _ = env_logger::try_init();

        let ts = PcapRecord::convert_packet_time(1527868899, 152053);

        let offset = std::time::Duration::from_secs(1527868899) + std::time::Duration::from_micros(152053);
        assert_eq!(ts, std::time::UNIX_EPOCH + offset);
    }
    #[test]
    fn parse_record() {
        let _ = env_logger::try_init();

        let data = [
            0x5Bu8, 0x11u8, 0x6Du8, 0xE3u8, //seconds, 1527868899
            0x00u8, 0x02u8, 0x51u8, 0xF5u8, //microseconds, 152053
            0x00u8, 0x00u8, 0x00u8, 0x12u8, //actual length, 32
            0x00u8, 0x00u8, 0x04u8, 0xD0u8, //original length, 1232
            //ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
            0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
            0x00u8, 0x04u8, //payload ethernet
            0x01u8, 0x02u8, 0x03u8, 0x04u8
        ];

        let (rem, record) = PcapRecord::parse(&data, nom::Endianness::Big).expect("Could not parse");

        assert!(rem.is_empty());

        let offset = std::time::Duration::from_secs(1527868899) + std::time::Duration::from_micros(152053);
        assert_eq!(*record.timestamp(), std::time::UNIX_EPOCH + offset);
        assert_eq!(record.actual_length(), 18);
        assert_eq!(record.original_length(), 1232);

        //TOOD: Add if other types
        /*
        let is_ethernet = if let Layer2::Ethernet(_) = record.layer2() {
            true
        } else {
            false
        };

        assert!(is_ethernet);
        */
    }
}