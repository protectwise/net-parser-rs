use crate::layer3::IPv4;
use std::collections::BTreeMap;
use nom::lib::std::collections::VecDeque;

const MAX_LEN: usize = 2 ^ 16 - 1;

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
struct Hole {
    start: usize,
    end: usize,
}

impl Default for Hole {
    fn default() -> Self {
        Hole {
            start: 0,
            end: MAX_LEN,
        }
    }
}

struct Holes {
    holes: VecDeque<Hole>,
}

impl Default for Holes {
    fn default() -> Self {
        let mut holes = VecDeque::new();
        holes.push_back(Hole::default());
        Self{
            holes
        }
    }
}

impl Holes {
    //https://tools.ietf.org/html/rfc815
    fn add(&mut self, frag_start: usize, frag_end: usize, last_frag: bool) -> bool {
        loop {
            if let Some(hole) = self.holes.pop_front() {
                if frag_start > hole.end || frag_end < hole.start { //Steps #2 and #3
                    self.holes.push_back(hole);
                    continue;
                }

                if frag_start > hole.start { //Step #5
                    let new_hole = Hole {
                        start: hole.start,
                        end: frag_end-1,
                    };
                    self.holes.push_back(new_hole);
                    continue;
                }

                if frag_end < hole.end && !last_frag { //Step #6
                    let new_hole = Hole {
                        start: frag_end + 1,
                        end: hole.end,
                    };
                    self.holes.push_back(new_hole);
                }
            } else {
                return true
            }
        }



    }
}
pub struct IPv4Defrag<'a>{
    holes: Holes,
    buffer: BTreeMap<usize, IPv4<'a>>,
    max_offset: Option<usize>,
}

impl <'a> IPv4Defrag<'a> {
    pub fn new() -> IPv4Defrag<'a> {
        IPv4Defrag {
            holes: Holes::default(),
            buffer: BTreeMap::new(),
            max_offset: None,
        }
    }


    pub fn add_packet(&mut self, ipv4: IPv4<'a>) -> Option<IPv4<'a>> {
        let flags = Flags::extract_flags(ipv4.flags);

        /*
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
         */

        None

    }
}