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
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Tcp Error")]
        Tcp(#[fail(cause)] tcp::errors::Error),
        #[fail(display = "Udp Error")]
        Udp(#[fail(cause)] udp::errors::Error),
        #[fail(display = "Vxlan Error")]
        Vxlan(#[fail(cause)] vxlan::errors::Error),
    }

    impl From<tcp::errors::Error> for Error {
        fn from(v: tcp::errors::Error) -> Self {
            Error::Tcp(v)
        }
    }

    impl From<self::udp::errors::Error> for Error {
        fn from(v: udp::errors::Error) -> Self {
            Error::Udp(v)
        }
    }

    impl From<self::vxlan::errors::Error> for Error {
        fn from(v: vxlan::errors::Error) -> Self {
            Error::Vxlan(v)
        }
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}