// SPDX-FileCopyrightText: © 2020 Etebase Authors
// SPDX-License-Identifier: LGPL-2.1-only

use std::error::Error as StdError;
use thiserror::Error;

use crate::http_client::ErrorResponse;

/// A short-hand version of a [`std::result::Result`] that always returns an Etebase [`enum@Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// The error type returned from the Etebase API
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    #[error("IO error")]
    Io(#[from] std::io::Error),

    #[error("URL parsing failed")]
    UrlParse(#[from] url::ParseError),

    #[error("MessagePack serialization failed")]
    MsgPackEncode(#[from] rmp_serde::encode::Error),
    #[error("MessagePack deserialization failed")]
    MsgPackDecode(#[from] rmp_serde::decode::Error),

    #[error("library usage error: {0}")]
    ProgrammingError(&'static str),
    #[error("attempted to fetch content of an item that doesn't have the content yet: {0}")]
    MissingContent(&'static str),
    #[error("base64 encoding/decoding failed: {0}")]
    Base64(&'static str),
    #[error("encryption error: {0}")]
    Encryption(&'static str),
    #[error("authorization error: {0}")]
    Unauthorized(ErrorResponse),
    #[error("data conflict: {0}")]
    Conflict(String),
    #[error("permission denied: {0}")]
    PermissionDenied(ErrorResponse),

    #[error("HTTP request failed: status {status}, {response}")]
    Http {
        status: u16,
        response: ErrorResponse,
    },

    #[error("network error")]
    Network(#[source] Box<dyn StdError>),
}
