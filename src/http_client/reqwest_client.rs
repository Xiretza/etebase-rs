use std::error::Error;

use reqwest::{
    blocking::{Client as ReqwestClient, RequestBuilder},
    header,
    redirect::Policy,
};

use super::client_impl::{ClientImplementation, Response};

static APP_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"),);

pub(super) struct Client {
    req_client: ReqwestClient,
}

impl Client {
    pub fn new(client_name: &str) -> Result<Self, crate::error::Error> {
        let req_client = ReqwestClient::builder()
            .user_agent(format!("{} {}", client_name, APP_USER_AGENT))
            .redirect(Policy::none())
            .build()
            .map_err(|e| crate::error::Error::Network(Box::new(e)))?;

        Ok(Self { req_client })
    }

    fn run_client(
        mut builder: RequestBuilder,
        auth_token: Option<&str>,
    ) -> Result<Response, Box<dyn Error>> {
        if let Some(auth_token) = auth_token {
            builder = builder.header(header::AUTHORIZATION, format!("Token {}", auth_token));
        }

        let resp = builder
            .header(header::CONTENT_TYPE, "application/msgpack")
            .header(header::ACCEPT, "application/msgpack")
            .send()?;
        let status = resp.status().as_u16();

        Ok(Response::new(status, resp.bytes()?.to_vec()))
    }
}

impl ClientImplementation for Client {
    fn get(&self, url: &str, auth_token: Option<&str>) -> Result<Response, Box<dyn Error>> {
        Self::run_client(self.req_client.get(url), auth_token)
    }

    fn post(
        &self,
        url: &str,
        auth_token: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Response, Box<dyn Error>> {
        Self::run_client(self.req_client.post(url).body(body), auth_token)
    }

    fn put(
        &self,
        url: &str,
        auth_token: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Response, Box<dyn Error>> {
        Self::run_client(self.req_client.put(url).body(body), auth_token)
    }

    fn patch(
        &self,
        url: &str,
        auth_token: Option<&str>,
        body: Vec<u8>,
    ) -> Result<Response, Box<dyn Error>> {
        Self::run_client(self.req_client.patch(url).body(body), auth_token)
    }

    fn delete(&self, url: &str, auth_token: Option<&str>) -> Result<Response, Box<dyn Error>> {
        Self::run_client(self.req_client.delete(url), auth_token)
    }
}
