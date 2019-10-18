use crate::Error;
use log::*;
use nom::*;

///
/// Collection of pcap records associated with a libpcap capture
#[derive(Clone, Debug)]
pub struct PcapRecords<'a> {
    inner: Vec<PcapRecord<'a>>,
}

impl<'a> PcapRecords<'a> {
    pub fn len(&self) -> usize { self.inner.len() }

    pub fn into_inner(self) -> Vec<PcapRecord<'a>> { self.inner }
    ///
    /// Parse a slice of bytes that correspond to a set of records, without libcap file format
    /// header (https://wiki.wireshark.org/Development/LibpcapFileFormat). Endianness of the byte
    /// slice must be known.
    ///
    pub fn parse<'b>(
        input: &'b [u8],
        endianness: Endianness,
    ) -> Result<(&'b [u8], PcapRecords<'b>), Error> {
        let mut records: std::vec::Vec<PcapRecord> = vec![];
        let mut current = input;

        trace!("{} bytes left for record parsing", current.len());

        loop {
            match PcapRecord::parse(current, endianness) {
                Ok((rem, r)) => {
                    current = rem;
                    trace!("{} bytes left for record parsing", current.len());
                    records.push(r);
                }
                Err(Error::Incomplete { size: opt_size }) => {
                    match opt_size {
                        None => debug!(
                            "Needed unknown number of bytes for parsing, only had {}",
                            current.len()
                        ),
                        Some(s) => debug!("Needed {} bytes for parsing, only had {:?}", s, current.len()),
                    }
                    break;
                }
                Err(e) => return Err(e),
            }
        }

        Ok((current, PcapRecords {
            inner: records
        }))
    }
}
///
/// Pcap record associated with a libpcap capture
///
#[derive(Clone, Copy, Debug)]
pub struct PcapRecord<'a> {
    pub timestamp: std::time::SystemTime,
    pub actual_length: u32,
    pub original_length: u32,
    pub payload: &'a [u8],
}

impl<'a> Default for PcapRecord<'a> {
    fn default() -> Self {
        PcapRecord {
            timestamp: std::time::SystemTime::UNIX_EPOCH,
            actual_length: 0,
            original_length: 0,
            payload: &[0u8; 0],
        }
    }
}

impl<'a> PcapRecord<'a> {
    ///
    /// Convert a packet time (seconds and partial second microseconds) to a system time (offset from epoch)
    ///
    pub fn convert_packet_time(ts_seconds: u32, ts_microseconds: u32) -> std::time::SystemTime {
        let offset = std::time::Duration::from_secs(ts_seconds as u64)
            + std::time::Duration::from_micros(ts_microseconds as u64);
        std::time::UNIX_EPOCH + offset
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
        }
    }

    pub fn parse<'b>(
        input: &'b [u8],
        endianness: nom::Endianness,
    ) -> Result<(&'b [u8], PcapRecord<'b>), Error> {
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
                    payload: payload
                })
        ).map_err(Error::from)
    }
}

impl<'a> std::fmt::Display for PcapRecord<'a> {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        self.timestamp
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_e| std::fmt::Error)
            .and_then(|d| {
                write!(
                    f,
                    "Timestamp={}{}   Length={}   Original Length={}",
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
    use super::*;

    use crate::flow::FlowExtraction;

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
            "Timestamp=1527868899152   Length=86   Original Length=1232"
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
        assert_eq!(record.timestamp, std::time::UNIX_EPOCH + offset);
        assert_eq!(record.actual_length, 86);
        assert_eq!(record.original_length, 1232);
    }

    #[test]
    fn convert_record() {
        let _ = env_logger::try_init();

        let (rem, record) =
            PcapRecord::parse(RAW_DATA, nom::Endianness::Big).expect("Could not parse");

        assert!(rem.is_empty());

        let flow = record.extract_flow().expect("Could not extract stream");
        assert_eq!(flow.source.port, 50871);
        assert_eq!(flow.destination.port, 80);
    }
}
