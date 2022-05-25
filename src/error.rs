// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::error::Error as StdError;
use std::fmt;

use crate::http_client::ErrorResponse;

/// A short-hand version of a [`std::result::Result`] that always returns an Etebase [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The error type returned from the Etebase API
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// An error with parsing the a URL (e.g. from the server URL)
    UrlParse(String),
    /// An error related to msgpack serialization and de-serialization
    MsgPack(String),
    /// A programming error that indicates the developers are using the API wrong
    ProgrammingError(&'static str),
    /// An attempt to fetch the content of an item that doesn't have the content yet
    MissingContent(&'static str),
    /// An issue with the padding of the encrypted content
    Padding(&'static str),
    /// An issue with the Base64 decoding
    Base64(&'static str),
    /// An issue with the encryption
    Encryption(&'static str),
    /// An authorization issue from the server
    Unauthorized(ErrorResponse),
    /// A conflict issue returned from the server, e.g. if a transaction failed
    Conflict(String),
    /// The operation was not allowed due to permissions
    PermissionDenied(ErrorResponse),

    /// A generic error with the server request
    Http {
        status: u16,
        response: ErrorResponse,
    },

    /// A network error from within the HTTP library
    Network(Box<dyn StdError>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[allow(clippy::match_same_arms)] // same order as in type declaration
        match self {
            Error::UrlParse(s) => s.fmt(f),
            Error::MsgPack(s) => s.fmt(f),
            Error::ProgrammingError(s) => s.fmt(f),
            Error::MissingContent(s) => s.fmt(f),
            Error::Padding(s) => s.fmt(f),
            Error::Base64(s) => s.fmt(f),
            Error::Encryption(s) => s.fmt(f),
            Error::PermissionDenied(s) => s.fmt(f),
            Error::Unauthorized(s) => s.fmt(f),
            Error::Conflict(s) => s.fmt(f),

            Error::Http { status, response } => write!(f, "HTTP status {}: {}", status, response),

            Error::Network(s) => s.fmt(f),
        }
    }
}

impl From<Error> for String {
    fn from(err: Error) -> String {
        err.to_string()
    }
}

impl StdError for Error {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        match self {
            Error::Network(e) => Some(&**e),
            _ => None,
        }
    }
}

impl From<url::ParseError> for Error {
    fn from(err: url::ParseError) -> Error {
        Error::UrlParse(err.to_string())
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Error {
        Error::UrlParse(err.to_string())
    }
}

impl From<rmp_serde::encode::Error> for Error {
    fn from(err: rmp_serde::encode::Error) -> Error {
        Error::MsgPack(err.to_string())
    }
}

impl From<rmp_serde::decode::Error> for Error {
    fn from(err: rmp_serde::decode::Error) -> Error {
        Error::MsgPack(err.to_string())
    }
}
