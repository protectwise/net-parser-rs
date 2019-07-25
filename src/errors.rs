use failure::Fail;

#[derive(Clone, Debug, Fail)]
pub enum Error {
    #[fail(display = "Incomplete: {:?}", size)]
    Incomplete { size: Option<usize> },
    #[fail(display = "{}", msg)]
    Failure { msg: String },
    #[fail(display = "{}", msg)]
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