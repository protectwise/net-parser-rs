pub mod tcp;
pub mod udp;
pub mod vxlan;

///
/// Available Layer 4 representations
///
pub enum Layer4<'a> {
    Tcp(tcp::Tcp<'a>),
    Udp(udp::Udp<'a>),
}

///
/// Information from Layer 4 protocols used in stream determination
///
pub struct Layer4FlowInfo {
    pub dst_port: u16,
    pub src_port: u16,
}

pub mod errors {
    use crate::layer4::tcp;
    use crate::layer4::udp;
    use crate::layer4::vxlan;
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
}
