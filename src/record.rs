use crate::{
    flow::{Device, Flow, FlowExtraction},
    layer2::{ethernet::Ethernet, Layer2, Layer2FlowInfo},
};

use log::*;
use nom::{Err as NomError, ErrorKind as NomErrorKind, *};

use std::{self, convert::TryFrom};

///
/// Pcap record associated with a libpcap capture
///
pub struct PcapRecord<'a> {
    timestamp: std::time::SystemTime,
    actual_length: u32,
    original_length: u32,
    payload: &'a [u8],
    flow: Option<Flow>,
}

impl<'a> Default for PcapRecord<'a> {
    fn default() -> Self {
        PcapRecord {
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            actual_length: 0,
            original_length: 0,
            payload: &[0u8; 0],
            flow: None,
        }
    }
}

impl<'a> PcapRecord<'a> {
    pub fn timestamp(&self) -> &std::time::SystemTime {
        &self.timestamp
    }
    pub fn actual_length(&self) -> u32 {
        self.actual_length
    }
    pub fn original_length(&self) -> u32 {
        self.original_length
    }
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    ///
    /// Convert a packet time (seconds and partial second microseconds) to a system time (offset from epoch)
    ///
    pub fn convert_packet_time(ts_seconds: u32, ts_microseconds: u32) -> std::time::SystemTime {
        let offset = std::time::Duration::from_secs(ts_seconds as u64)
            + std::time::Duration::from_micros(ts_microseconds as u64);
        std::time::UNIX_EPOCH + offset
    }

    ///
    /// Utility function to convert a vector of records to flows, unless an error is encountered in stream conversion
    ///
    pub fn convert_records<'b>(
        records: std::vec::Vec<PcapRecord<'b>>,
    ) -> std::vec::Vec<PcapRecord<'b>> {
        let mut records = records;
        let mut results = vec![];

        loop {
            if let Some(mut r) = records.pop() {
                match r.extract_flow() {
                    Ok(f) => {
                        r.flow = Some(f);
                        results.push(r);
                    }
                    Err(e) => {
                        debug!("Failed to extract stream: {}", e);
                    }
                }
            } else {
                break;
            }
        }

        results
    }

    pub fn new(
        timestamp: std::time::SystemTime,
        actual_length: u32,
        original_length: u32,
        payload: &'a [u8],
    ) -> PcapRecord<'a> {
        PcapRecord {
            timestamp: timestamp,
            actual_length: actual_length,
            original_length: original_length,
            payload: payload,
            flow: None,
        }
    }

    pub fn parse<'b>(
        input: &'b [u8],
        endianness: nom::Endianness,
    ) -> nom::IResult<&'b [u8], PcapRecord<'b>> {
        do_parse!(
            input,
            ts_seconds: u32!(endianness)
                >> ts_microseconds: u32!(endianness)
                >> actual_length: u32!(endianness)
                >> original_length: u32!(endianness)
                >> payload: take!(actual_length)
                >> (PcapRecord {
                    timestamp: PcapRecord::convert_packet_time(ts_seconds, ts_microseconds),
                    actual_length: actual_length,
                    original_length: original_length,
                    payload: payload,
                    flow: None
                })
        )
    }
}

impl<'a> FlowExtraction for PcapRecord<'a> {
    fn payload(&self) -> &[u8] {
        self.payload
    }
}

impl<'a> std::fmt::Display for PcapRecord<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| std::fmt::Error)
            .and_then(|d| {
                write!(
                    f,
                    "Timestamp={}{}   Length={}   Original Length={}",
                    d.as_secs(),
                    d.subsec_millis(),
                    self.actual_length,
                    self.original_length
                )
                .and_then(|_| {
                    if let Some(ref flw) = self.flow {
                        write!(f, "   Flow=").and_then(|_| flw.fmt(f))
                    } else {
                        write!(f, "   Flow=None")
                    }
                })
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
        0x00u8, 0x00u8, 0x00u8,
        0x56u8, //actual length, 86: 14 (ethernet) + 20 (ipv4 header) + 20 (tcp header) + 32 (tcp payload)
        0x00u8, 0x00u8, 0x04u8, 0xD0u8, //original length, 1232
        //ethernet
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
    fn display_record() {
        let _ = env_logger::try_init();

        let record = PcapRecord::parse(RAW_DATA, nom::Endianness::Big)
            .expect("Could not parse")
            .1;

        assert_eq!(
            format!("{}", record),
            "Timestamp=1527868899152   Length=86   Original Length=1232   Flow=None"
        );
    }

    #[test]
    fn convert_timestamp() {
        let _ = env_logger::try_init();

        let ts = PcapRecord::convert_packet_time(1527868899, 152053);

        let offset =
            std::time::Duration::from_secs(1527868899) + std::time::Duration::from_micros(152053);
        assert_eq!(ts, std::time::UNIX_EPOCH + offset);
    }

    #[test]
    fn parse_record() {
        let _ = env_logger::try_init();

        let (rem, record) =
            PcapRecord::parse(RAW_DATA, nom::Endianness::Big).expect("Could not parse");

        assert!(rem.is_empty());

        let offset =
            std::time::Duration::from_secs(1527868899) + std::time::Duration::from_micros(152053);
        assert_eq!(*record.timestamp(), std::time::UNIX_EPOCH + offset);
        assert_eq!(record.actual_length(), 86);
        assert_eq!(record.original_length(), 1232);
    }

    #[test]
    fn convert_record() {
        let _ = env_logger::try_init();

        let (rem, mut record) =
            PcapRecord::parse(RAW_DATA, nom::Endianness::Big).expect("Could not parse");

        assert!(rem.is_empty());

        let flow = record.extract_flow().expect("Could not extract stream");
        assert_eq!(flow.source().port(), 50871);
        assert_eq!(flow.destination().port(), 80);
    }
}
