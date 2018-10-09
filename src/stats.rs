use crate::Outcome;

/*
pub struct LayerNFlowInfo {
//    ...
//    next_layer: Option<LayerMFlowInfo>
    pub info: Info<L3Trace>,
}

// The idea I am thinking of switching to. This way
// All manner of traces can easily be created.
pub struct Info<I> {
    pub outcome: Outcome,
    pub trace: I,
}

// The type that would hold the information that
// should be traced. Can be an enum or a struct
// If the information is complex.
pub enum L3Trace {
    Try(usize), // Could be anything
    None,
}


// Simple PoC
fn some_function() {
    let info: Info<L3Trace> = Info {
        outcome: Outcome::Success,
        trace: L3Trace::Try(1337),
    };

    let flow_info = LayerNFlowInfo {
        info
    };

    match flow_info.info.trace {
        L3Trace::Try(n) => println!(n),
        _ => panic!(),
    };
}
*/