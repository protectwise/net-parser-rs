use crate::layer3::{IPv4, IPv4Flags};
use std::collections::{BTreeMap, HashMap};
use crate::layer3::ipv4::HEADER_LENGTH;

mod holes;
mod reassemble;

pub struct IPDefrag<'a> {
    sessions: HashMap<u16, IPDefragSession<'a>>
}

impl<'a> Default for IPDefrag<'a> {
    fn default() -> Self {
        IPDefrag {
            sessions: HashMap::new(),
        }

    }
}

pub struct IPDefragSession<'a>{
    holes: holes::Holes,
    buffer: BTreeMap<usize, IPv4<'a>>,
    reassembly_buffer: Vec<&'a [u8]>
}

impl <'a> IPDefragSession<'a> {
    pub fn new() -> IPDefragSession<'a> {
        IPDefragSession {
            holes: holes::Holes::default(),
            buffer: BTreeMap::new(),
            reassembly_buffer: vec![],
        }
    }

    fn extract_range_from_flags(flags: &IPv4Flags, total_len: usize) -> (usize, usize) {
        let start = flags.frag_offset as usize * 8;
        let end = start + (total_len - HEADER_LENGTH);
        (start, end)
    }

    pub fn add_packet(&mut self, ipv4: IPv4<'a>) -> Option<IPv4<'a>> {
        let flags = IPv4Flags::extract_flags(ipv4.flags);

        if !flags.more_frags && flags.frag_offset == 0 {
            return Some(ipv4);
        }

        let complete_session = if flags.more_frags  {
            let (start, end) = Self::extract_range_from_flags(&flags, ipv4.raw_length as _);
            self.buffer.insert(flags.frag_offset as _, ipv4);
            self.holes.add(start, end, false)
        } else {
            let (start, end) = Self::extract_range_from_flags(&flags, ipv4.raw_length as _);
            self.buffer.insert(flags.frag_offset as _, ipv4);
            self.holes.add(start, end, true)
        };

        if complete_session {
            let buffer = std::mem::take(&mut self.buffer).into_iter().map(|t|t.1).collect::<Vec<_>>();
            //reassemble::ipv4(buffer);
            //re-assemble
        }

        None

    }
}