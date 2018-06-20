pub mod prelude {
    pub use super::super::prelude::*;
    pub use super::super::layer3;
}

pub mod ethernet;

///
/// Layer2 types that can be parsed
///
pub enum Layer2<'a> {
    Ethernet(ethernet::Ethernet<'a>)
}
