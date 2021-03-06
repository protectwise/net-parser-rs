use crate::flow::Flow;
use crate::flow::errors::Error;
use crate::flow::info::layer2::{Info as L2Info};
use crate::flow::info::layer3::{Info as L3Info};
use crate::flow::info::layer4::{Id, Info as L4Info};
use crate::flow::layer4::FlowExtraction;
use crate::layer4::udp::Udp;

pub mod errors {
    use crate::errors::Error as NetParserError;
    use thiserror::{Error as ThisError};

    #[derive(Debug, ThisError)]
    pub enum Error {
        #[error("Error parsing UDP: {0:?}")]
        NetParser(#[from] NetParserError),
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}

impl<'a> FlowExtraction for Udp<'a> {
    fn extract_flow(&self, l2: L2Info, l3: L3Info) -> Result<Flow, Error> {
        Ok(Flow::new(
            l2,
            l3,
            L4Info {
                id: Id::Udp,
                dst_port: self.dst_port,
                src_port: self.src_port,
            }
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::MacAddress;
    use crate::flow::info::layer2::{Id as L2Id, Info as L2Info};
    use crate::flow::info::layer3::{Id as L3Id, Info as L3Info};
    use crate::flow::info::layer4::{Id as L4Id};
    use crate::layer4::udp::Udp;
    use crate::layer4::udp::tests::RAW_DATA;

    #[test]
    fn convert_udp() {
        let _ = env_logger::try_init();

        let (rem, l4) = Udp::parse(RAW_DATA).expect("Unable to parse");

        assert!(rem.is_empty());

        let l2 = L2Info {
            id: L2Id::Ethernet,
            src_mac: MacAddress::default(),
            dst_mac: MacAddress::default(),
            vlan: 0
        };

        let l3 = L3Info {
            id: L3Id::IPv4,
            src_ip: "0.0.0.0".parse().expect("Could not parse"),
            dst_ip: "0.0.0.0".parse().expect("Could not parse")
        };

        let info = l4.extract_flow(l2, l3).expect("Could not convert to layer 4 info");

        assert_eq!(info.layer2, L2Id::Ethernet);
        assert_eq!(info.layer3, L3Id::IPv4);
        assert_eq!(info.layer4, L4Id::Udp);
        assert_eq!(info.destination.port, 80);
        assert_eq!(info.source.port, 50871);
    }
}
