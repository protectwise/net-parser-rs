pub mod ethernet;

use crate::common::{MacAddress, Vlan, MAC_LENGTH};
use crate::flow::Flow;
use crate::flow::errors::Error;

pub trait FlowExtraction {
    fn extract_flow(&self) -> Result<Flow, Error>;
}

pub mod errors {
    use crate::flow::layer2::ethernet;
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Ethernet Error")]
        Ethernet(#[fail(cause)] ethernet::errors::Error),
    }

    impl From<ethernet::errors::Error> for Error {
        fn from(v: ethernet::errors::Error) -> Self {
            Error::Ethernet(v)
        }
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}