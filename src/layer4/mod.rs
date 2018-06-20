pub mod prelude {
    pub use super::super::prelude::*;
}

pub mod tcp;
pub mod udp;

///
/// Available Layer 4 representations
///
pub enum Layer4<'a> {
    Tcp(tcp::Tcp<'a>),
    Udp(udp::Udp<'a>)
}