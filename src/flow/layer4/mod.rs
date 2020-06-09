pub mod tcp;
pub mod udp;
pub mod vxlan;

use crate::flow::Flow;
use crate::flow::errors::Error;
use crate::flow::info::layer2::{Info as L2Info};
use crate::flow::info::layer3::{Info as L3Info};

pub trait FlowExtraction {
    fn extract_flow(&self, l2: L2Info, l3: L3Info) -> Result<Flow, Error>;
}

///
/// Errors encountered during layer4 flow extraction
///
pub mod errors {
    use crate::flow::layer4::tcp;
    use crate::flow::layer4::udp;
    use crate::flow::layer4::vxlan;
    use thiserror::{Error as ThisError};

    #[derive(Debug, ThisError)]
    pub enum Error {
        #[error("Tcp Error: {0:?}")]
        Tcp(#[from] tcp::errors::Error),
        #[error("Udp Error: {0:?}")]
        Udp(#[from] udp::errors::Error),
        #[error("Vxlan Error: {0:?}")]
        Vxlan(#[from] vxlan::errors::Error),
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}