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
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "ARP Error")]
        Arp(#[fail(cause)] arp::errors::Error),
        #[fail(display = "IPv4 Error")]
        IPv4(#[fail(cause)] ipv4::errors::Error),
        #[fail(display = "IPv6 Error")]
        IPv6(#[fail(cause)] ipv6::errors::Error)
    }

    impl From<arp::errors::Error> for Error {
        fn from(v: arp::errors::Error) -> Self {
            Error::Arp(v)
        }
    }

    impl From<ipv4::errors::Error> for Error {
        fn from(v: ipv4::errors::Error) -> Self {
            Error::IPv4(v)
        }
    }

    impl From<ipv6::errors::Error> for Error {
        fn from(v: ipv6::errors::Error) -> Self {
            Error::IPv6(v)
        }
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}