use crate::layer2;
use failure::Fail;

#[derive(Debug, Fail)]
pub enum Error {
    #[fail(display = "Nom error while parsing layer4")]
    Nom(#[fail(cause)] failure::Error),
    #[fail(display = "Layer2 error while parsing")]
    L2(#[fail(cause)] layer2::errors::Error),
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

unsafe impl Sync for Error {}
unsafe impl Send for Error {}