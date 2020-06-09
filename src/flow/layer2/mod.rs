pub mod ethernet;

use crate::flow::Flow;
use crate::flow::errors::Error;

pub trait FlowExtraction {
    fn extract_flow(&self) -> Result<Flow, Error>;
}

pub mod errors {
    use crate::flow::layer2::ethernet;
    use thiserror::{Error as ThisError};

    #[derive(Debug, ThisError)]
    pub enum Error {
        #[error("Ethernet Error")]
        Ethernet(#[from] ethernet::errors::Error),
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}