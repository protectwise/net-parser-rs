use crate::layer3::IPv4;
use crate::layer3::ipv4::Payload;
use crate::flow::layer3::ipv4::errors::{Error as Ipv4Error};

pub fn ipv4<'a>(first: IPv4<'a>, buffer: Vec<IPv4<'a>>) -> Result<IPv4<'a>, Ipv4Error> {
    let mut buffer = buffer;
    let mut first = first;
    let mut payload = Vec::new();
    payload.extend_from_slice(&first.payload);

    for packet in buffer.into_iter() {
        payload.extend_from_slice(&packet.payload);
    }
    first.payload = Payload::Owned(payload);
    Ok(first)
}