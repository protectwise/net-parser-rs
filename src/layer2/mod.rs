pub mod prelude {
    pub use super::super::prelude::*;
    pub use super::super::layer3;
}

pub mod ethernet;

pub enum Layer2<'a> {
    Ethernet(ethernet::Ethernet<'a>)
}
