use crate::flow::Flow;
use crate::flow::errors::Error;
use crate::flow::info::layer2::{Id, Info};
use crate::flow::layer2::FlowExtraction;
use crate::flow::layer2::errors::{Error as L2Error};
use crate::flow::layer3::{FlowExtraction as Layer3Extraction};
use crate::layer2::ethernet::{Ethernet, EthernetTypeId, Layer3Id};
use crate::layer3::{IPv4, IPv6, Arp};

use log::*;

use std::convert::TryFrom;

pub mod errors {
    use crate::flow::layer3;
    use crate::layer2::ethernet::EthernetTypeId;
    use crate::nom_error;
    use failure::{err_msg, Fail};

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Failed parse of {:?}: {}", l3, err)]
        Nom {
            l3: EthernetTypeId,
            #[fail(cause)] err: nom_error::Error
        },
        #[fail(display = "Incomplete parse of {:?}: {}", l3, size)]
        Incomplete {
            l3: EthernetTypeId,
            size: usize
        },
        #[fail(display = "Unknown Ethernet Type: {:?}", etype)]
        EthernetType {
            etype: EthernetTypeId
        },
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}

impl<'a> FlowExtraction for Ethernet<'a> {
    fn extract_flow(&self) -> Result<Flow, Error> {
        let l2 = Info {
            id: Id::Ethernet,
            src_mac: self.src_mac.clone(),
            dst_mac: self.dst_mac.clone(),
            vlan: self.vlan(),
        };

        let ether_type = self.ether_type.clone();
        debug!(
            "Creating from layer 3 type {:?} using payload of {}B",
            ether_type,
            self.payload.len()
        );

        match ether_type {
            EthernetTypeId::L3(Layer3Id::IPv4) => {
                IPv4::parse(&self.payload)
                    .map_err(|ref e| {
                        #[cfg(feature = "log-errors")]
                        error!("Error parsing ipv4 {:?}", e);
                        let e: L2Error = errors::Error::Nom {
                            l3: ether_type.clone(),
                            err: e.into()
                        }.into();
                        e.into()
                    })
                    .and_then(|r| {
                        let (rem, l3) = r;
                        if rem.is_empty() {
                            l3.extract_flow(l2)
                        } else {
                            let e: L2Error = errors::Error::Incomplete {
                                l3: ether_type.clone(),
                                size: rem.len()
                            }.into();
                            Err(e.into())
                        }
                    })
            }
            EthernetTypeId::L3(Layer3Id::IPv6) => {
                IPv6::parse(&self.payload)
                    .map_err(|ref e| {
                        #[cfg(feature = "log-errors")]
                        error!("Error parsing ipv6 {:?}", e);
                        let e: L2Error = errors::Error::Nom {
                            l3: ether_type.clone(),
                            err: e.into()
                        }.into();
                        e.into()
                    })
                    .and_then(|r| {
                        let (rem, l3) = r;
                        if rem.is_empty() {
                            l3.extract_flow(l2)
                        } else {
                            let e: L2Error = errors::Error::Incomplete {
                                l3: ether_type.clone(),
                                size: rem.len()
                            }.into();
                            Err(e.into())
                        }
                    })
            }
            EthernetTypeId::L3(Layer3Id::Arp) => {
                Arp::parse(&self.payload)
                    .map_err(|ref e| {
                        #[cfg(feature = "log-errors")]
                        error!("Error parsing arp {:?}", e);
                        let e: L2Error = errors::Error::Nom {
                            l3: ether_type.clone(),
                            err: e.into()
                        }.into();
                        e.into()
                    })
                    .and_then(|r| {
                        let (rem, l3) = r;
                        if rem.is_empty() {
                            l3.extract_flow(l2)
                        } else {
                            let e: L2Error = errors::Error::Incomplete {
                                l3: ether_type.clone(),
                                size: rem.len()
                            }.into();
                            Err(e.into())
                        }
                    })
            }
            _ => {
                let e: L2Error = errors::Error::EthernetType {
                    etype: ether_type
                }.into();
                Err(e.into())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use hex_slice::AsHex;

    use super::*;

    use crate::flow::info::layer2::{Id as L2Id};
    use crate::layer2::ethernet::Ethernet;
    use crate::layer2::ethernet::tests::TCP_RAW_DATA;

    #[test]
    fn convert_ethernet_tcp() {
        let _ = env_logger::try_init();

        let (rem, l2) = Ethernet::parse(TCP_RAW_DATA).expect("Could not parse");

        assert!(rem.is_empty());

        let info = l2.extract_flow().expect("Could not convert to layer 2 stream info");

        assert_eq!(info.layer2, L2Id::Ethernet);
        assert_eq!(info.source.port, 50871);
        assert_eq!(info.destination.port, 80);
    }
}
