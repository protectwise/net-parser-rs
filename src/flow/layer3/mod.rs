pub mod arp;
pub mod ipv4;
pub mod ipv6;

use crate::flow::Flow;
use crate::flow::errors::Error;
use crate::flow::info::layer2::Info;

pub trait FlowExtraction {
    fn extract_flow(&self, l2: Info) -> Result<Flow, Error>;
}

///
/// Errors encountered during layer3 flow extraction
///
pub mod errors {
    use crate::flow::layer3::arp;
    use crate::flow::layer3::ipv4;
    use crate::flow::layer3::ipv6;
    use thiserror::{Error as ThisError};

    #[derive(Debug, ThisError)]
    pub enum Error {
        #[error("ARP Error: {0:?}")]
        Arp(#[from] arp::errors::Error),
        #[error("IPv4 Error: {0:?}")]
        IPv4(#[from] ipv4::errors::Error),
        #[error("IPv6 Error: {0:?}")]
        IPv6(#[from] ipv6::errors::Error)
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}