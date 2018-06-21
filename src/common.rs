use std;

pub const MAC_LENGTH: usize = 6;

#[derive(Debug, PartialEq, Eq)]
pub struct MacAddress(pub [u8; MAC_LENGTH]);

pub type Vlan = u16;

pub type Port = u16;

impl std::fmt::Display for MacAddress {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
               self.0[0],
               self.0[1],
               self.0[2],
               self.0[3],
               self.0[4],
               self.0[5],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_mac_address() {
        let mac = MacAddress([0u8, 1u8, 2u8, 3u8, 4u8, 5u8]);

        assert_eq!(format!("{}", mac), "00:01:02:03:04:05".to_string());
    }
}