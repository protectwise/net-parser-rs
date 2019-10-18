pub mod ethernet;

pub use ethernet::Ethernet as Ethernet;

///
/// Layer2 types that can be parsed
///
#[derive(Clone, Debug)]
pub enum Layer2<'a> {
    Ethernet(ethernet::Ethernet<'a>),
}
