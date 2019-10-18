use crate::Error as NetParserError;
use crate::flow::{layer2, layer3, layer4};
use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "NetParserError error while parsing layer2")]
    NetParser(#[fail(cause)] NetParserError),
    #[fail(display = "Layer2 error while parsing")]
    L2(#[fail(cause)] layer2::errors::Error),
    #[fail(display = "Layer3 error while parsing")]
    L3(#[fail(cause)] layer3::errors::Error),
    #[fail(display = "Layer4 error while parsing")]
    L4(#[fail(cause)] layer4::errors::Error),
    #[fail(display = "Parse was incomplete: {}", size)]
    Incomplete {
        size: usize
    }
}

impl From<layer2::errors::Error> for Error {
    fn from(v: layer2::errors::Error) -> Self {
        Error::L2(v)
    }
}

impl From<layer3::errors::Error> for Error {
    fn from(v: layer3::errors::Error) -> Self {
        Error::L3(v)
    }
}

impl From<layer4::errors::Error> for Error {
    fn from(v: layer4::errors::Error) -> Self {
        Error::L4(v)
    }
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}