use std::{error::Error as StdError, fmt::Display};

// Error type definition
//

/// Errors emitted by this library.
#[derive(Debug)]
pub enum Error {
    Json(serde_json::Error),
    JWT(josekit::JoseError),
    InvalidStructure,
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Error {
        Error::Json(e)
    }
}

impl From<josekit::JoseError> for Error {
    fn from(e: josekit::JoseError) -> Error {
        Error::JWT(e)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Json(e) => e.fmt(f),
            Error::JWT(e) => e.fmt(f),
            Error::InvalidStructure => f.write_str("Incorrect jwe structure"),
        }
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Json(e) => Some(e),
            Error::JWT(e) => Some(e),
            _ => None,
        }
    }
}
