use crate::{common::*, layer3::Layer3FlowInfo};

pub mod ethernet;

///
/// Layer2 types that can be parsed
///
pub enum Layer2<'a> {
    Ethernet(ethernet::Ethernet<'a>),
}

///
/// Information from Layer 2 protocols used in stream determination
///
pub struct Layer2FlowInfo {
    pub src_mac: MacAddress,
    pub dst_mac: MacAddress,
    pub vlan: Vlan,
    pub layer3: Layer3FlowInfo,
}

pub mod errors {
    use crate::layer2::ethernet;
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
