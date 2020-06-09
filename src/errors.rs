use thiserror::{Error as ThisError};

#[derive(Clone, Debug, ThisError)]
pub enum Error {
    #[error("Incomplete: {0:?}", size)]
    Incomplete { size: Option<usize> },
    #[error("{0}", msg)]
    Failure { msg: String },
    #[error("{0}", msg)]
    Custom { msg: String },
}

unsafe impl Sync for Error {}
unsafe impl Send for Error {}

impl<I, E> From<nom::Err<I, E>> for Error
    where
        I: std::fmt::Debug,
        E: std::fmt::Debug,
{
    fn from(err: nom::Err<I, E>) -> Self {
        Error::from(&err)
    }
}

impl<I, E> From<&nom::Err<I, E>> for Error
    where
        I: std::fmt::Debug,
        E: std::fmt::Debug,
{
    fn from(err: &nom::Err<I, E>) -> Self {
        match err {
            nom::Err::Incomplete(nom::Needed::Unknown) => {
                Error::Incomplete {
                    size: None
                }
            }
            nom::Err::Incomplete(nom::Needed::Size(sz)) => {
                Error::Incomplete {
                    size: Some(*sz)
                }
            }
            nom::Err::Error(c) => {
                Error::Failure {
                    msg: format!("Error: {:?}", c)
                }
            }
            nom::Err::Failure(c) => {
                Error::Failure {
                    msg: format!("Failure: {:?}", c)
                }
            }
        }
    }
}