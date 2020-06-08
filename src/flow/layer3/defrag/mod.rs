use crate::layer3::IPv4;
use std::collections::BTreeMap;
use nom::lib::std::collections::VecDeque;
use crate::layer3::ipv4::HEADER_LENGTH;


mod holes;

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

pub struct IPv4Defrag<'a>{
    holes: holes::Holes,
    buffer: BTreeMap<usize, IPv4<'a>>,
}

impl <'a> IPv4Defrag<'a> {
    pub fn new() -> IPv4Defrag<'a> {
        IPv4Defrag {
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

        if flags.more_frags  {
            let (start, end) = Self::extract_range_from_flags(&flags, ipv4.raw_length as _);
            self.buffer.insert(flags.frag_offset as _, ipv4);
            self.holes.add(start, end, false);
        } else if flags.frag_offset != 0 {
            let (start, end) = Self::extract_range_from_flags(&flags, ipv4.raw_length as _);
            self.buffer.insert(flags.frag_offset as _, ipv4);
            self.holes.add(start, end, true);
        } else { // more flags was false and the offset is 0 == no fragmentation
            return Some(ipv4);
        }

        None

    }
}