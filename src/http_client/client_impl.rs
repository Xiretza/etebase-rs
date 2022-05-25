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
#[must_use = "The server may have responded with an error, which should be checked for using Response::check_status"]
pub struct Response {
    pub status: u16,
    body: Vec<u8>,
}

impl Response {
    /// Creates a new `Response` object from an HTTP status code and a response body.
    pub fn new(status: u16, body: Vec<u8>) -> Response {
        Response { status, body }
    }

    /// Get the response body as bytes, without checking the HTTP status code. To verify the status
    /// code, use [`body()`](Self::body).
    #[must_use]
    pub fn body_unchecked(&self) -> &[u8] {
        &self.body
    }

    /// Checks the HTTP response status for success and returns the response body as bytes.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`](crate::error::Error::Http) if the HTTP response code indicated an
    /// error.
    pub fn body(&self) -> Result<&[u8], crate::error::Error> {
        self.check_status().map(|()| self.body.as_slice())
    }

    /// Checks the HTTP response status for success.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Http`](crate::error::Error::Http) if the HTTP response code indicated an
    /// error.
    pub fn check_status(&self) -> Result<(), crate::error::Error> {
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
