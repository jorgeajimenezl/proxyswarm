use std::{
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use crate::error::Error;
use hyper::{header::PROXY_AUTHENTICATE, http::uri, Response};

#[derive(Clone, PartialEq, Debug)]
pub enum AuthenticationScheme {
    Basic,
    Digest,
    None,
}

#[derive(Clone, Debug)]
pub struct Credentials {
    pub username: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub enum ProxyType {
    Http,
    Https,
}

#[derive(Clone, Debug)]
pub struct Proxy {
    pub addr: SocketAddr,
    pub kind: ProxyType,
    pub credentials: Option<Credentials>,
}

impl Proxy {
    pub fn get_auth_info<B>(
        response: &'_ Response<B>,
    ) -> Result<(AuthenticationScheme, Option<&'_ str>), Error> {
        let data = match response.headers().get(PROXY_AUTHENTICATE) {
            Some(d) => d.to_str()?,
            None => return Ok((AuthenticationScheme::None, None)),
        };

        // This must be right since hyper keep a valid structure
        let (auth, _) = data.split_once(' ').ok_or("Invalid digest structure")?;

        if auth.eq_ignore_ascii_case("digest") {
            return Ok((AuthenticationScheme::Digest, Some(data)));
        }
        if auth.eq_ignore_ascii_case("basic") {
            return Ok((AuthenticationScheme::Basic, Some(data)));
        }
        Err("Unknow auth scheme method".into())
    }
}

impl FromStr for Proxy {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let url = uri::Uri::from_str(s).map_err(|_| format!("`{s}` is not a valid proxy URL"))?;

        let kind = match url.scheme_str() {
            Some(scheme) => match scheme {
                "http" => ProxyType::Http,
                "https" => ProxyType::Https,
                _ => return Err(format!("`{scheme}` proxy scheme is not accepted").into()),
            },
            None => ProxyType::Http,
        };

        let addr = match url.host() {
            Some(host) => {
                let port = url.port_u16().unwrap_or(match kind {
                    ProxyType::Http => 80,
                    ProxyType::Https => 443,
                });
                let mut iter = (host, port)
                    .to_socket_addrs()
                    .map_err(|_| format!("`{host}` could not be resolved"))?;
                iter.next()
                    .ok_or(format!("`{host}` does not resolve to a usable IP address"))?
            }
            _ => return Err(format!("`{s}` not contains host").into()),
        };

        let credentials = match url
            .authority()
            .and_then(|x| x.as_str().split_once('@'))
            .map(|x| x.0)
        {
            Some(auth) => match auth.split_once(':') {
                Some((u, p)) => Some(Credentials {
                    username: u.to_string(),
                    password: p.to_string(),
                }),
                None => Some(Credentials {
                    username: auth.to_string(),
                    password: String::from(""),
                }),
            },
            None => None,
        };

        Ok(Proxy {
            addr,
            credentials,
            kind,
        })
    }
}
