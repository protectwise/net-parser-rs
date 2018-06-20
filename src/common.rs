pub const MAC_LENGTH: usize = 6;

#[derive(Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; MAC_LENGTH]);

pub type Vlan = u16;

pub type Port = u16;