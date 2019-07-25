use crate::flow::Flow;
use crate::flow::errors::Error;
use crate::flow::info::layer2::{Info as L2Info};
use crate::flow::info::layer3::{Info as L3Info};
use crate::flow::layer2::{FlowExtraction as Layer2Extraction};
use crate::flow::layer4::FlowExtraction;
use crate::layer2::ethernet::Ethernet;
use crate::layer4::Vxlan;

use log::*;

pub mod errors {
    use crate::errors::Error as NetParserError;
    use crate::layer2::ethernet::EthernetTypeId;
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Error parsing Vxlan")]
        NetParser(#[fail(cause)] NetParserError),
        #[fail(display = "Incomplete parse of {:?}: {}", l3, size)]
        Incomplete {
            l3: EthernetTypeId,
            size: usize
        },
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}

impl<'a> FlowExtraction for Vxlan<'a> {
    fn extract_flow(&self, _l2: L2Info, _l3: L3Info) -> Result<Flow, Error> {
        Ethernet::parse(self.payload)
            .map_err(|e| {
                error!("Error parsing ethernet {:?}", e);
                Error::L4(errors::Error::NetParser(e).into())
            })
            .and_then(|r| {
                let (rem, l2) = r;
                if rem.is_empty() {
                    l2.extract_flow()
                } else {
                    Err(Error::L4(errors::Error::Incomplete {
                        l3: l2.ether_type,
                        size: rem.len()
                    }.into()))
                }
            })
    }
}