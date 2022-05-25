// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::error::Error as StdError;
use std::fmt;
use thiserror::Error;

use crate::http_client::ErrorResponse;

/// A short-hand version of a [`std::result::Result`] that always returns an Etebase [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The error type returned from the Etebase API
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// An IO error
    Io(#[from] std::io::Error),

    /// An error with parsing the a URL (e.g. from the server URL)
    UrlParse(#[from] url::ParseError),

    /// An error related to msgpack serialization
    MsgPackEncode(#[from] rmp_serde::encode::Error),
    /// An error related to msgpack deserialization
    MsgPackDecode(#[from] rmp_serde::decode::Error),

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
    Network(#[source] Box<dyn StdError>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        #[allow(clippy::match_same_arms)] // same order as in type declaration
        match self {
            Error::Io(s) => s.fmt(f),
            Error::UrlParse(s) => s.fmt(f),
            Error::MsgPackEncode(s) => s.fmt(f),
            Error::MsgPackDecode(s) => s.fmt(f),
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
