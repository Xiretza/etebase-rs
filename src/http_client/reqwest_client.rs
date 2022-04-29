use reqwest::{
    blocking::{Client as ReqwestClient, RequestBuilder},
    header,
    redirect::Policy,
};

use crate::error::{Error, Result};

use super::client_impl::{ClientImplementation, Response};

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

impl From<reqwest::Error> for Error {
    fn from(err: reqwest::Error) -> Error {
        if err.is_builder() || err.is_timeout() || err.is_redirect() {
            Error::Generic(err.to_string())
        } else {
            Error::Connection(err.to_string())
        }
    }
}

pub(super) struct Client {
    req_client: ReqwestClient,
}

impl Client {
    pub fn new(client_name: &str) -> Result<Self> {
        let req_client = ReqwestClient::builder()
            .user_agent(format!("{} {}", client_name, APP_USER_AGENT))
            .redirect(Policy::none())
            .build()?;

        Ok(Self { req_client })
    }

    fn with_auth_header(builder: RequestBuilder, auth_token: Option<&str>) -> RequestBuilder {
        match auth_token {
            Some(auth_token) => {
                builder.header(header::AUTHORIZATION, format!("Token {}", auth_token))
            }
            None => builder,
        }
    }

    fn with_base_headers(builder: RequestBuilder) -> RequestBuilder {
        builder
            .header(header::CONTENT_TYPE, "application/msgpack")
            .header(header::ACCEPT, "application/msgpack")
    }

    fn prep_client(builder: RequestBuilder, auth_token: Option<&str>) -> RequestBuilder {
        Self::with_base_headers(Self::with_auth_header(builder, auth_token))
    }

    fn get_inner(&self, url: &str, auth_token: Option<&str>) -> Result<Response> {
        let req = Self::prep_client(self.req_client.get(url), auth_token);
        let resp = req.send()?;
        let status = resp.status().as_u16();
        Ok(Response::new(resp.bytes()?.to_vec(), status))
    }

    fn post_inner(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Result<Response> {
        let req = Self::prep_client(self.req_client.post(url), auth_token).body(body);
        let resp = req.send()?;
        let status = resp.status().as_u16();
        Ok(Response::new(resp.bytes()?.to_vec(), status))
    }

    fn put_inner(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Result<Response> {
        let req = Self::prep_client(self.req_client.put(url), auth_token).body(body);
        let resp = req.send()?;
        let status = resp.status().as_u16();
        Ok(Response::new(resp.bytes()?.to_vec(), status))
    }

    fn patch_inner(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Result<Response> {
        let req = Self::prep_client(self.req_client.patch(url), auth_token).body(body);
        let resp = req.send()?;
        let status = resp.status().as_u16();
        Ok(Response::new(resp.bytes()?.to_vec(), status))
    }

    fn delete_inner(&self, url: &str, auth_token: Option<&str>) -> Result<Response> {
        let req = Self::prep_client(self.req_client.delete(url), auth_token);
        let resp = req.send()?;
        let status = resp.status().as_u16();
        Ok(Response::new(resp.bytes()?.to_vec(), status))
    }
}

impl ClientImplementation for Client {
    fn get(&self, url: &str, auth_token: Option<&str>) -> Response {
        match self.get_inner(url, auth_token) {
            Ok(resp) => resp,
            Err(err) => Response::new_err(err),
        }
    }

    fn post(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response {
        match self.post_inner(url, auth_token, body) {
            Ok(resp) => resp,
            Err(err) => Response::new_err(err),
        }
    }

    fn put(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response {
        match self.put_inner(url, auth_token, body) {
            Ok(resp) => resp,
            Err(err) => Response::new_err(err),
        }
    }

    fn patch(&self, url: &str, auth_token: Option<&str>, body: Vec<u8>) -> Response {
        match self.patch_inner(url, auth_token, body) {
            Ok(resp) => resp,
            Err(err) => Response::new_err(err),
        }
    }

    fn delete(&self, url: &str, auth_token: Option<&str>) -> Response {
        match self.delete_inner(url, auth_token) {
            Ok(resp) => resp,
            Err(err) => Response::new_err(err),
        }
    }
}
