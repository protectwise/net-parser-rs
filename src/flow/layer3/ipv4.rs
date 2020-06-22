use crate::flow::Flow;
use crate::flow::errors::Error;
use crate::flow::info::layer2::{Info as L2Info};
use crate::flow::info::layer3::{Id, Info};
use crate::flow::layer3::FlowExtraction;
use crate::flow::layer3::errors::{Error as L3Error};
use crate::flow::layer4::{FlowExtraction as Layer4Extraction};
use crate::layer3::{InternetProtocolId, IPv4};
use crate::layer4::{Tcp, Udp};

use log::*;

pub mod errors {
    use crate::errors::Error as NetParserError;
    use crate::layer3::InternetProtocolId;
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Failed parse of {:?}: {}", l4, err)]
        NetParser {
            l4: InternetProtocolId,
            #[fail(cause)] err: NetParserError
        },
        #[fail(display = "Incomplete parse of {:?}: {}", l4, size)]
        Incomplete {
            l4: InternetProtocolId,
            size: usize
        },
        #[fail(display = "Unknown type while parsing IPv4: {:?}", id)]
        InternetProtocolId {
            id: InternetProtocolId
        },
        #[fail(display = "Fragment")]
        Fragment,
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}

impl<'a> FlowExtraction for IPv4<'a> {
    fn extract_flow(&self, l2: L2Info) -> Result<Flow, Error> {
        let l3 = Info {
            id: Id::IPv4,
            src_ip: self.src_ip,
            dst_ip: self.dst_ip
        };
        debug!("Creating stream info from {:?}", self.protocol);
        let proto = self.protocol.clone();
        match proto {
            InternetProtocolId::Tcp => {
                Tcp::parse(&self.payload).map_err(|e| {
                    error!("Error parsing tcp {:?}", e);
                    let e: L3Error = errors::Error::NetParser {
                        l4: proto.clone(),
                        err: e
                    }.into();
                    e.into()
                })
                    .and_then(|r| {
                        let (rem, l4) = r;
                        if rem.is_empty() {
                            l4.extract_flow(l2, l3)
                        } else {
                            let e: L3Error = errors::Error::Incomplete {
                                l4: proto.clone(),
                                size: rem.len()
                            }.into();
                            Err(e.into())
                        }
                    })
            }
            InternetProtocolId::Udp => {
                Udp::parse(&self.payload).map_err(|e| {
                    #[cfg(feature = "logging")]
                    error!("Error parsing udp {:?}", e);
                    let e: L3Error = errors::Error::NetParser {
                        l4: proto.clone(),
                        err: e
                    }.into();
                    e.into()
                })
                    .and_then(|r| {
                        let (rem, l4) = r;
                        if rem.is_empty() {
                            l4.extract_flow(l2, l3)
                        } else {
                            let e: L3Error = errors::Error::Incomplete {
                                l4: proto.clone(),
                                size: rem.len()
                            }.into();
                            Err(e.into())
                        }
                    })
            }
            _ => {
                let e: L3Error = errors::Error::InternetProtocolId {
                    id: proto.clone()
                }.into();
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::common::MacAddress;
    use crate::flow::info::layer2::{Id as L2Id, Info as L2Info};
    use crate::flow::info::layer3::{Id as L3Id};
    use crate::layer3::ipv4::IPv4;
    use crate::layer3::ipv4::tests::RAW_DATA;

    #[test]
    fn convert_ipv4() {
        let _ = env_logger::try_init();

        let (_, l3) = IPv4::parse(RAW_DATA).expect("Unable to parse");

        let l2 = L2Info {
            id: L2Id::Ethernet,
            src_mac: MacAddress::default(),
            dst_mac: MacAddress::default(),
            vlan: 0
        };

        let info = l3.extract_flow(l2).expect("Could not convert to layer 3 info");

        assert_eq!(info.layer3, L3Id::IPv4);
        assert_eq!(
            info.source.ip,
            "1.2.3.4"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(
            info.destination.ip,
            "10.11.12.13"
                .parse::<std::net::IpAddr>()
                .expect("Could not parse ip address")
        );
        assert_eq!(info.source.port, 50871);
        assert_eq!(info.destination.port, 80);
    }
}