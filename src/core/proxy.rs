use hyper::{header::PROXY_AUTHORIZATION, HeaderMap, Method, Request, Uri};

use super::auth::basic::basic_compute_response;
use super::auth::digest::digest_compute_response;
use super::utils::{generate_rand_hex, split_once};

#[derive(Clone, PartialEq, Debug)]
pub struct ProxyDigestInfo {
    pub realm: Option<String>,
    pub domain: Option<String>,
    pub uri: Option<String>,
    pub nonce: Option<String>,
    pub opaque: Option<String>,
    pub stale: Option<String>,
    pub algorithm: Option<String>,
    pub qop: Option<String>,
}

#[derive(Clone, PartialEq, Debug)]
pub enum ProxyAuthentication {
    Unknown,
    Basic,
    Digest(ProxyDigestInfo),
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

pub fn add_authentication_headers<B>(
    authentication: ProxyAuthentication,
    credentials: Credentials,
    req: &mut Request<B>,
) {
    match authentication {
        ProxyAuthentication::Basic => {
            req.headers_mut().insert(
                PROXY_AUTHORIZATION,
                get_auth_basic_response(credentials).parse().unwrap(),
            );
        }
        ProxyAuthentication::Digest(info) => {
            let uri = req.uri().clone();
            let method = req.method().clone();

            req.headers_mut().insert(
                PROXY_AUTHORIZATION,
                get_auth_digest_response(credentials, &uri, &method, info, 1)
                    .parse()
                    .unwrap(),
            );
        }
        _ => (),
    }
}

fn get_auth_basic_response(credentials: Credentials) -> String {
    let r = basic_compute_response(&credentials.username, &credentials.password);
    format!("Basic {}", r)
}

fn get_auth_digest_response(
    credentials: Credentials,
    uri: &Uri,
    method: &Method,
    info: ProxyDigestInfo,
    nc: u32,
) -> String {
    let uri = format!(
        "{}",
        (if method == Method::CONNECT {
            uri.authority().map(|x| x.as_str()).unwrap()
        } else {
            uri.path()
        })
    );
    let cnonce = generate_rand_hex(32);

    let s = digest_compute_response(
        &credentials.username,
        &credentials.password,
        info.realm.as_deref().unwrap(),
        info.algorithm.as_deref(),
        info.nonce.as_deref().unwrap(),
        &cnonce,
        nc,
        info.qop.as_deref(),
        method.as_str(),
        &uri,
    );

    let mut response = format!(
        "Digest username=\"{}\", realm=\"{}\", nonce=\"{}\", uri=\"{}\", ",
        &credentials.username,
        info.realm.as_deref().unwrap(),
        info.nonce.as_deref().unwrap(),
        uri
    );
    if let Some(x) = info.qop {
        response += format!("cnonce=\"{}\", nc={:08x}, qop={}, ", cnonce, nc, x).as_str();
    }
    if let Some(x) = info.opaque {
        response += format!("opaque=\"{}\", ", x).as_str();
    }
    response += format!("response=\"{}\"", s).as_str();
    response
}

pub fn get_proxy_auth_info(s: &str) -> ProxyAuthentication {
    let (tauth, v) = split_once(&s, " ").unwrap();

    match tauth {
        "Digest" => {
            let mut digest = ProxyDigestInfo {
                realm: None,
                domain: None,
                uri: None,
                nonce: None,
                opaque: None,
                stale: None,
                algorithm: None,
                qop: None,
            };

            for spec in v.split(",").map(|x| x.trim()) {
                let (key, value) = split_once(&spec, "=").unwrap();
                let v = value.replace("\"", "");

                match key {
                    "realm" => digest.realm = Some(v),
                    "domain" => digest.domain = Some(v),
                    "uri" => digest.uri = Some(v),
                    "nonce" => digest.nonce = Some(v),
                    "opaque" => digest.opaque = Some(v),
                    "stale" => digest.stale = Some(v),
                    "algorithm" => digest.algorithm = Some(v),
                    "qop" => digest.qop = Some(v),
                    _ => (), // log: WARNING unspected proxy value
                }
            }

            ProxyAuthentication::Digest(digest)
        }
        "Basic" => ProxyAuthentication::Basic,
        _ => ProxyAuthentication::Unknown,
    }
}
