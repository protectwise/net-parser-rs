pub mod device;
pub mod errors;
pub mod info;
pub mod layer2;
pub mod layer3;
pub mod layer4;

use crate::common::Vlan;
use crate::layer2::ethernet::Ethernet;
use crate::PcapRecord;

use device::Device;
use errors::Error;
use layer2::{FlowExtraction as Layer2Extraction};
use log::*;

///
/// Trait that provides necessary information to indicate a flow
///
pub trait FlowExtraction {
    fn payload(&self) -> &[u8];

    fn extract_flow(&self) -> Result<Flow, Error> {
        trace!("Creating stream from payload of {}B", self.payload().len());

        let payload_ref = self.payload();

        Ethernet::parse(payload_ref)
            .map_err(|e| {
                error!("Error parsing ethernet {:?}", e);
                Error::NetParser(e)
            })
            .and_then(|r| {
                let (rem, l2) = r;
                if rem.is_empty() {
                    l2.extract_flow()
                } else {
                    Err(Error::Incomplete { size: rem.len() })
                }
            })
    }
}

impl<'a> FlowExtraction for PcapRecord<'a> {
    fn payload(&self) -> &[u8] {
        self.payload
    }
}

///
/// Flow that was built from a record moved
///
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Flow {
    pub source: Device,
    pub destination: Device,
    pub layer2: info::layer2::Id,
    pub layer3: info::layer3::Id,
    pub layer4: info::layer4::Id,
    pub vlan: Vlan,
}

impl Flow {
    pub fn new(
        l2: info::layer2::Info,
        l3: info::layer3::Info,
        l4: info::layer4::Info
    ) -> Flow {
        Flow {
            source: Device {
                mac: l2.src_mac,
                ip: l3.src_ip,
                port: l4.src_port
            },
            destination: Device {
                mac: l2.dst_mac,
                ip: l3.dst_ip,
                port: l4.dst_port
            },
            layer2: l2.id,
            layer3: l3.id,
            layer4: l4.id,
            vlan: l2.vlan
        }
    }
}

impl std::fmt::Display for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "Source=[{}]   Destination=[{}]   Vlan={}",
            self.source, self.destination, self.vlan
        )
    }
}

///
/// Utility function to convert a vector of records to flows, unless an error is encountered in stream conversion
///
pub fn convert_records<'b>(
    records: Vec<PcapRecord<'b>>,
) -> Vec<(PcapRecord<'b>, Flow)> {
    let mut records = records;
    let mut results = vec![];

    loop {
        if let Some(r) = records.pop() {
            match r.extract_flow() {
                Ok(f) => {
                    results.push( (r, f) );
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

#[cfg(test)]
mod tests {
    use crate::common::MacAddress;
    use crate::flow::info::layer2::{Id as L2Id};
    use crate::flow::info::layer3::{Id as L3Id};
    use crate::flow::info::layer4::{Id as L4Id};
    use super::*;

    use std::io::Read;
    use std::path::PathBuf;

    #[test]
    fn format_flow() {
        let flow = Flow {
            layer2: L2Id::Ethernet,
            layer3: L3Id::IPv4,
            layer4: L4Id::Tcp,
            source: Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(0, 1, 2, 3)),
                mac: MacAddress([0u8, 1u8, 2u8, 3u8, 4u8, 5u8]),
                port: 80,
            },
            destination: Device {
                ip: std::net::IpAddr::V4(std::net::Ipv4Addr::new(100, 99, 98, 97)),
                mac: MacAddress([11u8, 10u8, 9u8, 8u8, 7u8, 6u8]),
                port: 52436,
            },
            vlan: 0,
        };

        assert_eq!(format!("{}", flow), "Source=[Mac=00:01:02:03:04:05   Ip=0.1.2.3   Port=80]   Destination=[Mac=0b:0a:09:08:07:06   Ip=100.99.98.97   Port=52436]   Vlan=0")
    }

    #[test]
    fn file_convert() {
        let _ = env_logger::try_init();

        let pcap_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("resources")
            .join("4SICS-GeekLounge-151020.pcap");

        let pcap_reader = std::fs::File::open(pcap_path.clone())
            .expect(&format!("Failed to open pcap path {:?}", pcap_path));

        let bytes = pcap_reader
            .bytes()
            .map(|b| b.unwrap())
            .collect::<std::vec::Vec<u8>>();

        let (_, f) =
            crate::CaptureFile::parse(&bytes).expect("Failed to parse");

        assert_eq!(f.global_header.endianness, nom::Endianness::Little);
        assert_eq!(f.records.len(), 246137);

        let converted_records = convert_records(f.records.into_inner());

        assert_eq!(converted_records.len(), 236527);
    }
}
