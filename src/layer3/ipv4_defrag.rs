use crate::layer3::IPv4;
use std::collections::BTreeMap;

pub struct IPv4Defrag<'a>{
    fragments: BTreeMap<usize, IPv4<'a>>,
    max_offset: Option<usize>,
}

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

impl <'a> IPv4Defrag<'a> {
    pub fn new() -> IPv4Defrag<'a> {
        IPv4Defrag {
            fragments: HashMap::new(),
            max_offset: None,
        }
    }


    pub fn add_packet(&mut self, ipv4: IPv4<'a>) -> Option<IPv4<'a>> {
        let flags = Flags::extract_flags(ipv4.flags);


        if flags.more_frags  {
            self.fragments.insert(flags.frag_offset as _, ipv4);
        } else if flags.frag_offset != 0 {
            self.fragments.insert(flags.frag_offset as _, ipv4);
            self.max_offset = Some(flags.frag_offset as _);
        } else { // more flags was false and the offset is 0 == no fragmentation
            return Some(ipv4);
        }

        if let Some(max_ofset) = self.max_offset {
            let expected_fragments = max_ofset / 8;
            if self.fragments.len() == expected_fragments {
                let mut buf: Vec<u8> = vec![0; max_ofset];
                for (_, frag) in self.fragments.into_iter() {
                    buf.extend_from_slice(frag.payload)
                }
            }
        }

        None

    }
}