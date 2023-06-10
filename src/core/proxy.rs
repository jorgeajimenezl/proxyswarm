use hyper::{
    header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    HeaderMap, Request, Response, Uri,
};

use super::utils::split_once;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use digest_auth::AuthContext;
use std::io::{self, Error, ErrorKind};

#[derive(Clone, PartialEq, Debug)]
pub enum ProxyAuthentication<'a> {
    Unknown,
    Basic,
    Digest(&'a str),
    None,
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct Proxy {
    pub uri: Uri,
    pub headers: HeaderMap,
    pub credentials: Option<Credentials>,
}

impl Proxy {
    pub fn add_authentication_headers<B>(
        &self,
        authentication: ProxyAuthentication,
        req: &mut Request<B>,
    ) -> io::Result<()> {
        let credentials = (&self.credentials).as_ref().ok_or(Error::new(
            ErrorKind::Other,
            "The proxy require credentials and it not was given",
        ))?;

        match authentication {
            ProxyAuthentication::Basic => {
                let cred = format!("{}:{}", credentials.username, credentials.password);

                req.headers_mut().insert(
                    PROXY_AUTHORIZATION,
                    format!("Basic {}", STANDARD.encode(cred)).parse().unwrap(),
                );
            }
            ProxyAuthentication::Digest(www_authenticate) => {
                let uri = req.uri().to_string();
                let method = req.method().to_string();

                let context = AuthContext::new_with_method(
                    &credentials.username,
                    &credentials.password,
                    &uri,
                    Option::<&'_ [u8]>::None,
                    digest_auth::HttpMethod::from(method),
                );
                let mut prompt = digest_auth::parse(www_authenticate).unwrap();
                let response = prompt.respond(&context);

                req.headers_mut().insert(
                    PROXY_AUTHORIZATION,
                    response.unwrap().to_header_string().parse().unwrap(),
                );
            }
            _ => (),
        }

        Ok(())
    }

    pub fn get_auth_info<T>(
        response: &Response<T>,
    ) -> Result<ProxyAuthentication, hyper::header::ToStrError> {
        let data = match response.headers().get(PROXY_AUTHENTICATE) {
            Some(d) => d.to_str()?,
            None => return Ok(ProxyAuthentication::None),
        };

        let (auth, _) = split_once(&data, " ").unwrap();

        Ok(match auth {
            "Digest" => ProxyAuthentication::Digest(data.into()),
            "Basic" => ProxyAuthentication::Basic,
            _ => ProxyAuthentication::Unknown,
        })
    }
}
