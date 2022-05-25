use std::error::Error;

use serde::Deserialize;

use crate::http_client::ErrorResponse;

/// A trait for implementing a custom [network client](crate::Client)
pub trait ClientImplementation {
    /// Makes a GET request
    fn get(&self, url: &str, auth_token: Option<&str>) -> Result<Response, Box<dyn Error>>;

    /// Makes a POST request
    fn post(
        &self,
        url: &str,
        auth_token: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Response, Box<dyn Error>>;

    /// Makes a PUT request
    fn put(
        &self,
        url: &str,
        auth_token: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Response, Box<dyn Error>>;

    /// Makes a PATCH request
    fn patch(
        &self,
        url: &str,
        auth_token: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Response, Box<dyn Error>>;

    /// Makes a DELETE request
    fn delete(&self, url: &str, auth_token: Option<&str>) -> Result<Response, Box<dyn Error>>;
}

/// An network response as returned from [network clients](ClientImplementation)
#[derive(Clone, PartialEq, Eq, Debug)]
#[must_use = "The server may have responded with an error, which should be checked for using Response::error_for_status"]
pub struct Response {
    pub status: u16,
    body: Vec<u8>,
}

impl Response {
    /// Creates a new `Response` object from an HTTP status code and a response body.
    pub fn new(status: u16, body: Vec<u8>) -> Response {
        Response { status, body }
    }

    /// Get the response body as bytes
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.body
    }

    /// Returns [`Ok`] for valid responses and an [`Error`] object on error
    pub fn error_for_status(&self) -> Result<(), crate::error::Error> {
        #[derive(Deserialize)]
        struct ErrorResponseInner {
            pub code: Option<String>,
            pub detail: Option<String>,
        }

        if self.status >= 200 && self.status < 300 {
            return Ok(());
        }

        let response = match rmp_serde::from_slice(&self.body) {
            Ok(ErrorResponseInner { code, detail }) => ErrorResponse::Error { code, detail },
            Err(_) => ErrorResponse::Invalid {
                body: self.body.clone(),
            },
        };

        Err(crate::error::Error::Http {
            status: self.status,
            response,
        })
    }
}
