use crate::flow::Flow;
use crate::flow::errors::Error;
use crate::flow::info::layer2::Info;
use crate::flow::layer3::FlowExtraction;
use crate::layer3::Arp;

use arrayref::array_ref;
use log::*;
use nom::{Err as NomError, ErrorKind as NomErrorKind, *};

use std::{self, convert::TryFrom};

pub mod errors {
    use crate::nom_error;
    use failure::Fail;

    #[derive(Debug, Fail)]
    pub enum Error {
        #[fail(display = "Nom error while parsing ARP")]
        Nom(#[fail(cause)] nom_error::Error),
        #[fail(display = "ARP cannot be converted to a flow")]
        Flow,
    }

    unsafe impl Sync for Error {}
    unsafe impl Send for Error {}
}

impl FlowExtraction for Arp {
    fn extract_flow(&self, l2: Info) -> Result<Flow, Error> {
        Err(Error::L3(errors::Error::Flow.into()))
    }
}