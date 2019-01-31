pub mod tcp;
pub mod udp;
pub mod vxlan;

pub use tcp::Tcp as Tcp;
pub use udp::Udp as Udp;
pub use vxlan::Vxlan as Vxlan;

///
/// Available Layer 4 representations
///
pub enum Layer4<'a> {
    Tcp(Tcp<'a>),
    Udp(Udp<'a>),
    Vxlan(Vxlan<'a>),
}
