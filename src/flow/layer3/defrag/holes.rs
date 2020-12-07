
#[derive(Debug)]
struct Hole {
    start: usize,
    end: usize,
}

impl Default for Hole {
    fn default() -> Self {
        Hole {
            start: 0,
            end: usize::MAX,
        }
    }
}

pub struct Holes {
    holes: Vec<Hole>,
}

impl Default for Holes {
    fn default() -> Self {
        let mut holes = Vec::new();
        holes.push(Hole::default());
        Self{
            holes
        }
    }
}

impl Holes {
    //https://tools.ietf.org/html/rfc815
    pub fn add(&mut self, frag_start: usize, frag_end: usize, last_frag: bool) -> bool {
        let mut new_holes = vec![];
        for hole in std::mem::take(&mut self.holes) {
            if frag_start > hole.end || frag_end < hole.start { //Steps #2 and #3
                new_holes.push(hole);
                continue;
            }
            if frag_start > hole.start { //Step #5
                let new_hole = Hole {
                    start: hole.start,
                    end: frag_start-1,
                };
                new_holes.push(new_hole);
            }

            if frag_end < hole.end && !last_frag { //Step #6
                let new_hole = Hole {
                    start: frag_end + 1,
                    end: hole.end,
                };
                new_holes.push(new_hole);
            }
        }
        if new_holes.is_empty() {
            true
        } else {
            self.holes = new_holes;
            false
        }
    }
}

#[cfg(test)]
pub mod tests {
    use super::*;
    use rand::seq::SliceRandom;

    fn create_frags() -> Vec<(Hole, bool)> {
        let step = 10;
        let mut frags = vec![];
        for frag_start in (0..100).step_by(step) {
            let frag = Hole{
                start: frag_start,
                end: frag_start + step -1,
            };

            frags.push((frag, false));
        }
        if let Some((frag, end)) = frags.last_mut() {
            *end = true;
        }
        frags
    }

    #[test]
    fn handle_sequence_asc() {
        let frags = create_frags();
        println!("Frags {:?}", frags);
        let mut holes = Holes::default();

        let result = frags.into_iter().map(|(f, last)| {
           holes.add(f.start, f.end, last)
        }).collect::<Vec<bool>>().last().map(|f| *f).unwrap();

        assert_eq!(result, true);
    }

    #[test]
    fn handle_sequence_desc() {
        let mut frags = create_frags();
        frags.reverse();
        println!("Frags {:?}", frags);
        let mut holes = Holes::default();

        let result = frags.into_iter().map(|(f, last)| {
            holes.add(f.start, f.end, last)
        }).collect::<Vec<bool>>().last().map(|f| *f).unwrap();

        assert_eq!(result, true);
    }

    #[test]
    fn handle_sequence_random() {
        let mut rng = rand::thread_rng();
        let mut frags = create_frags();
        frags.shuffle(&mut rng);
        println!("Frags {:?}", frags);
        let mut holes = Holes::default();

        let result = frags.into_iter().map(|(f, last)| {
            holes.add(f.start, f.end, last)
        }).collect::<Vec<bool>>().last().map(|f| *f).unwrap();

        assert_eq!(result, true);
    }
}