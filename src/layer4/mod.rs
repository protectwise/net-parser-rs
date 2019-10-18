pub mod tcp;
pub mod udp;
pub mod vxlan;

pub use tcp::Tcp as Tcp;
pub use udp::Udp as Udp;
pub use vxlan::Vxlan as Vxlan;

///
/// Available Layer 4 representations
///
#[derive(Clone, Copy, Debug)]
pub enum Layer4<'a> {
    Tcp(Tcp<'a>),
    Udp(Udp<'a>),
    Vxlan(Vxlan<'a>),
}

impl<'a> Layer4<'a> {
    pub fn as_bytes(&self) -> Vec<u8> {
        match self {
            Layer4::Tcp(v) => v.as_bytes(),
            Layer4::Udp(v) => v.as_bytes(),
            Layer4::Vxlan(v) => v.as_bytes(),
        }
    }
}
