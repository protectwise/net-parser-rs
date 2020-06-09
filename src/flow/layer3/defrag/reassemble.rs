use crate::layer3::IPv4;
use crate::flow::layer3::ipv4::errors::{Error as Ipv4Error};

pub fn ipv4<'a>(buffer: Vec<IPv4<'a>>) -> Result<IPv4, Ipv4Error> {
    let mut buffer = buffer;
    if buffer.is_empty() {
        return Err(Ipv4Error::Defrag{msg: String::from("empty buffer")})
    }
    let mut first = buffer.remove(0);
    let mut payload = Vec::new();
    payload.extend_from_slice(first.payload);

    for packet in buffer.into_iter() {
        payload.extend_from_slice(packet.payload);
    }
    std::mem::replace(&mut first.payload, payload.as_slice());
    Ok(first)
}