use std::{
    net::{SocketAddr, ToSocketAddrs},
    str::FromStr,
};

use crate::error::Error;
use hyper::{header::PROXY_AUTHENTICATE, Response};

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
        let url = url::Url::parse(s).map_err(|_| format!("`{s}` is not a valid proxy URL"))?;

        let scheme = url.scheme();
        let kind = match ["http", "https"]
            .iter()
            .position(|x| x.eq_ignore_ascii_case(scheme))
            .ok_or(format!("`{scheme}` proxy scheme is not accepted"))?
        {
            0 => ProxyType::Http,
            1 => ProxyType::Https,
            _ => todo!(),
        };

        let addr = url
            .socket_addrs(|| None)?
            .into_iter()
            .next()
            .ok_or(format!("`{s}` does not resolve to a usable IP address"))?;

        let credentials = if url.username() == "" && url.password().is_none() {
            None
        } else {
            let username = String::from(url.username());
            let password = String::from(url.password().unwrap_or(""));
            Some(Credentials { username, password })
        };

        Ok(Proxy {
            addr,
            credentials,
            kind,
        })
    }
}
