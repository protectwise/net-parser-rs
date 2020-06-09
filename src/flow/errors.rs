use crate::Error as NetParserError;
use crate::flow::{layer2, layer3, layer4};
use thiserror::{Error as ThisError};

#[derive(Debug, ThisError)]
pub enum Error {
    #[error("NetParserError error while parsing layer2")]
    NetParser(#[from] NetParserError),
    #[error("Layer2 error while parsing")]
    L2(#[from] layer2::errors::Error),
    #[error("Layer3 error while parsing")]
    L3(#[from] layer3::errors::Error),
    #[error("Layer4 error while parsing")]
    L4(#[from] layer4::errors::Error),
    #[error("Parse was incomplete: {0}", size)]
    Incomplete {
        size: usize
    }
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}