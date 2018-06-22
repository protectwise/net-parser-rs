use super::prelude::*;

use super::{
    flow,
    layer2::{
        Layer2,
        Layer2FlowInfo,
        ethernet::Ethernet
    }
};

use self::nom::*;

use std;
use std::convert::TryFrom;

///
/// Pcap record associated with a libpcap capture
///
pub struct PcapRecord{
    endianness: nom::Endianness,
    timestamp: std::time::SystemTime,
    actual_length: u32,
    original_length: u32,
    payload: std::vec::Vec<u8>
}

impl PcapRecord {
    pub fn endianness(&self) -> nom::Endianness { self.endianness }
    pub fn timestamp(&self) -> &std::time::SystemTime {
        &self.timestamp
    }
    pub fn actual_length(&self) -> u32 {
        self.actual_length
    }
    pub fn original_length(&self) -> u32 {
        self.original_length
    }
    pub fn payload(&self) -> &std::vec::Vec<u8> { &self.payload }

    pub fn convert_packet_time(ts_seconds: u32, ts_microseconds: u32) -> std::time::SystemTime {
        let offset = std::time::Duration::from_secs(ts_seconds as u64) + std::time::Duration::from_micros(ts_microseconds as u64);
        std::time::UNIX_EPOCH + offset
    }

    pub fn new(
        endianness: nom::Endianness,
        timestamp: std::time::SystemTime,
        actual_length: u32,
        original_length: u32,
        payload: std::vec::Vec<u8>
    ) -> PcapRecord {
        PcapRecord {
            endianness,
            timestamp,
            actual_length,
            original_length,
            payload
        }
    }

    pub fn parse(input: &[u8], endianness: nom::Endianness) -> nom::IResult<&[u8], PcapRecord> {
        do_parse!(input,

            ts_seconds: u32!(endianness) >>
            ts_microseconds: u32!(endianness) >>
            actual_length: u32!(endianness) >>
            original_length: u32!(endianness) >>
            payload: take!(actual_length) >>

            (
                PcapRecord {
                    endianness: endianness,
                    timestamp: PcapRecord::convert_packet_time(ts_seconds, ts_microseconds),
                    actual_length: actual_length,
                    original_length: original_length,
                    payload: payload.into()
                }
            )
        )
    }
}

impl std::fmt::Display for PcapRecord {
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

impl TryFrom<PcapRecord> for flow::Flow {
    type Error = errors::Error;

    fn try_from(value: PcapRecord) -> Result<Self, Self::Error> {
        let l2 = Ethernet::parse(value.payload().as_slice(), value.endianness())
            .map_err(|e| {
                let err: Self::Error = e.into();
                err
            }).and_then(|r| {
            let (rem, l2) = r;
            if rem.is_empty() {
                Layer2FlowInfo::try_from(l2)
            } else {
                Err(errors::Error::from_kind(errors::ErrorKind::IncompleteParse(rem.len())))
            }
        })?;

        Ok(Flow {
            source: flow::Device {
                mac: l2.src_mac,
                ip: l2.layer3.src_ip,
                port: l2.layer3.layer4.src_port
            },
            destination: flow::Device {
                mac: l2.dst_mac,
                ip: l2.layer3.dst_ip,
                port: l2.layer3.layer4.dst_port
            },
            record: value,
            vlan: l2.vlan
        })
    }
}

#[cfg(test)]
mod tests {
    extern crate env_logger;

    use super::*;

    const RAW_DATA: &'static [u8] = &[
        0x5Bu8, 0x11u8, 0x6Du8, 0xE3u8, //seconds, 1527868899
        0x00u8, 0x02u8, 0x51u8, 0xF5u8, //microseconds, 152053
        0x00u8, 0x00u8, 0x00u8, 0x51u8, //actual length, 81: 14 (ethernet) + 20 (ipv4 header) + 15 (tcp header) + 32 (tcp payload)
        0x00u8, 0x00u8, 0x04u8, 0xD0u8, //original length, 1232
        //ethernet
        0x01u8, 0x02u8, 0x03u8, 0x04u8, 0x05u8, 0x06u8, //dst mac 01:02:03:04:05:06
        0xFFu8, 0xFEu8, 0xFDu8, 0xFCu8, 0xFBu8, 0xFAu8, //src mac FF:FE:FD:FC:FB:FA
        0x08u8, 0x00u8, //ipv4
        //ipv4
        0x45u8, //version and header length
        0x00u8, //tos
        0x00u8, 0x43u8, //length, 20 bytes for header, 45 bytes for ethernet
        0x00u8, 0x00u8, //id
        0x00u8, 0x00u8, //flags
        0x64u8, //ttl
        0x06u8, //protocol, tcp
        0x00u8, 0x00u8, //checksum
        0x01u8, 0x02u8, 0x03u8, 0x04u8, //src ip 1.2.3.4
        0x0Au8, 0x0Bu8, 0x0Cu8, 0x0Du8, //dst ip 10.11.12.13
        //tcp
        0x80u8, //length, 8 words (32 bytes)
        0xC6u8, 0xB7u8, //src port, 50871
        0x00u8, 0x50u8, //dst port, 80
        0x00u8, 0x00u8, 0x00u8, 0x01u8, //sequence number, 1
        0x00u8, 0x00u8, 0x00u8, 0x02u8, //acknowledgement number, 2
        0x00u8, 0x00u8, //flags, 0
        0x01u8, 0x02u8, 0x03u8, 0x04u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0x00u8, 0x00u8, 0x00u8, 0x00u8,
        0xfcu8, 0xfdu8, 0xfeu8, 0xffu8 //payload, 8 words (32 bytes)
    ];

    #[test]
    fn display_record() {
        let _ = env_logger::try_init();

        let record = PcapRecord::parse(RAW_DATA, nom::Endianness::Big).expect("Could not parse").1;

        assert_eq!(format!("{}", record), "Timestamp=1527868899152   Length=81   Original Length=1232");
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

        let (rem, record) = PcapRecord::parse(RAW_DATA, nom::Endianness::Big).expect("Could not parse");

        assert!(rem.is_empty());

        let offset = std::time::Duration::from_secs(1527868899) + std::time::Duration::from_micros(152053);
        assert_eq!(*record.timestamp(), std::time::UNIX_EPOCH + offset);
        assert_eq!(record.actual_length(), 81);
        assert_eq!(record.original_length(), 1232);
    }

    #[test]
    fn convert_record() {
        let _ = env_logger::try_init();

        let (rem, record) = PcapRecord::parse(RAW_DATA, nom::Endianness::Big).expect("Could not parse");

        assert!(rem.is_empty());

        let info = flow::Flow::try_from(record).expect("Could not extract flow");

        assert_eq!(info.source().port, 50871);
        assert_eq!(info.destination().port, 80);
    }
}