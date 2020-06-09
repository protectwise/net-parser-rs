use crate::layer3::IPv4;
use std::collections::BTreeMap;
use nom::lib::std::collections::VecDeque;
use crate::layer3::ipv4::HEADER_LENGTH;

mod holes;
mod reassemble;

struct Flags {
    do_not_frag: bool,
    more_frags: bool,
    frag_offset: u16,
}

impl Flags {
    fn extract_flags(flags: u16) -> Flags {
        let frag_offset = flags & 8191; // 0001,1111,1111,1111
        let flags = flags >> 13;
        let more_frags = flags & 1 == 1;
        let do_not_frag = flags & 2 == 1;
        Flags {
            do_not_frag,
            more_frags,
            frag_offset
        }
    }
}

pub struct IPDefragSession<'a>{
    holes: holes::Holes,
    buffer: BTreeMap<usize, IPv4<'a>>,
}

impl <'a> IPDefragSession<'a> {
    pub fn new() -> IPDefragSession<'a> {
        IPDefragSession {
            holes: holes::Holes::default(),
            buffer: BTreeMap::new(),
        }
    }

    fn extract_range_from_flags(flags: &Flags, total_len: usize) -> (usize, usize) {
        let start = flags.frag_offset as usize * 8;
        let end = start + (total_len - HEADER_LENGTH);
        (start, end)
    }

    pub fn add_packet(&mut self, ipv4: IPv4<'a>) -> Option<IPv4<'a>> {
        let flags = Flags::extract_flags(ipv4.flags);

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
            reassemble::ipv4(buffer);
            //re-assemble
        }

        None

    }
}