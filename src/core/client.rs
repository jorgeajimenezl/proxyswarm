// WARNING: IMPLEMENT POOL
// use futures::future::poll_fn;
use hyper::{
    self,
    client::{conn::Builder, connect::HttpConnector, Client},
    header::{HOST, PROXY_AUTHENTICATE},
    service::Service,
    Body, Method, Request, Response, StatusCode,
};
use log::{debug, error, trace, warn};
use std::io::{Error, ErrorKind};
use tokio::{self, net::TcpStream};

#[derive(Clone)]
pub struct ProxyClient {
    proxies: Vec<Proxy>,
    baypass: Vec<String>,
}

use super::proxy::{add_authentication_headers, get_proxy_auth_info, Proxy, ProxyAuthentication};

#[inline]
fn io_err<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> Error {
    Error::new(ErrorKind::Other, e)
}

impl ProxyClient {
    // pub fn new() -> Self {
    //     ProxyClient {
    //         proxies: Vec::new(),
    //         baypass: Vec::new()
    //     }
    // }

    pub fn from_parts(proxies: Vec<Proxy>, baypass: Vec<String>) -> Self {
        ProxyClient {
            proxies: proxies,
            baypass: baypass,
        }
    }

    // pub fn from_proxy(proxy: Proxy) -> Self {
    //     ProxyClient {
    //         proxies: vec![proxy],
    //         baypass: Vec::new()
    //     }
    // }

    // pub fn add_baypass_uri(&mut self, uri: &str) {
    //     self.baypass.push(String::from(uri));
    // }

    // pub fn add_proxy(&mut self, proxy: Proxy) {
    //     self.proxies.push(proxy);
    // }

    // pub fn proxies(&self) -> &[Proxy] {
    //     return &self.proxies;
    // }

    pub async fn request(&self, rid: u32, req: Request<Body>) -> Result<Response<Body>, Error> {
        for host in self.baypass.iter() {
            if req.uri().host().unwrap_or_default() == host {
                // TODO: FIX THIS
                debug!(
                    "[#{}] Request forwared directly to original destination",
                    rid
                );
                return Client::new()
                    .request(req)
                    .await
                    .map_err(|e| io_err::<hyper::Error>(e.into()));
            }
        }
        let mut connector = HttpConnector::new();
        connector.set_nodelay(true);

        for proxy in self.proxies.iter() {
            let stream = match connector.call(proxy.uri.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("[#{}] Proxy {} is unavailable: {}", rid, proxy.uri, e);
                    continue;
                }
            };

            let (mut req_sender, connection) = Builder::new()
                .handshake::<TcpStream, Body>(stream)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            // spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                let _ = connection.await;
            });

            let fake = Request::builder()
                .uri(req.uri())
                .method(if req.method() == Method::CONNECT {
                    Method::CONNECT
                } else {
                    Method::TRACE
                })
                .version(req.version())
                .header(
                    HOST,
                    req.uri().authority().map(|a| a.as_str()).ok_or(Error::new(
                        ErrorKind::Other,
                        format!(
                            "[#{}] Unable to get authority section in the request uri",
                            rid
                        ),
                    ))?,
                )
                .body(Body::empty())
                .unwrap();

            trace!("[#{}] Request: {:?}", rid, fake);
            debug!("[#{}] Forwarding request to the proxy", rid);
            let res = req_sender
                .send_request(fake)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            // If proxy don't say 407 just redirect the request
            if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                trace!("[#{}] Proxy don't require authentication", rid);
                return Ok(res);
            }
            debug!("[#{}] Proxy require authentication", rid);

            let headers = res.headers();
            let auth_info = get_proxy_auth_info(match headers.get(PROXY_AUTHENTICATE) {
                Some(d) => d
                    .to_str()
                    .map_err(|e| io_err::<hyper::header::ToStrError>(e.into()))?,
                None => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        format!(
                            "[#{}] Unable to get authentication scheme from proxy",
                            rid
                        ),
                    ));
                }
            });

            let mut fake = Request::builder()
                .uri(req.uri())
                .method(req.method())
                .version(req.version())
                .header(HOST, req.uri().authority().map(|a| a.as_str()).unwrap())
                .body(Body::empty())
                .unwrap();

            // Add proxy authorization headers
            if auth_info != ProxyAuthentication::None {
                add_authentication_headers(
                    auth_info,
                    proxy.credentials.clone().ok_or(Error::new(
                        ErrorKind::Other,
                        format!(
                            "[#{}] The proxy require credentials and it not was given",
                            rid
                        ),
                    ))?,
                    &mut fake,
                );
            }
            let stream = match connector.call(proxy.uri.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "[#{}] Proxy {} is unavailable to resolve authentication challenge: {}",
                        rid, proxy.uri, e
                    );
                    continue;
                }
            };

            let (mut req_sender, connection) = Builder::new()
                .handshake::<TcpStream, Body>(stream)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            if req.method() == Method::CONNECT {
                let id = rid;
                tokio::spawn(async move {
                    let parts = match connection.without_shutdown().await {
                        Ok(v) => v,
                        Err(e) => {
                            error!("[#{}] Unable to get underline stream: {}", id, e);
                            return;
                        }
                    };
                    let mut io = parts.io;

                    match hyper::upgrade::on(req).await {
                        Ok(mut upgraded) => {
                            // Proxying data
                            let (from_client, from_server) =
                                match tokio::io::copy_bidirectional(&mut upgraded, &mut io).await {
                                    Ok(v) => v,
                                    Err(e) => {
                                        error!("[#{}] Server io error: {}", id, e);
                                        return;
                                    }
                                };

                            // Print message when done
                            debug!(
                                "[#{}] Client wrote {} bytes and received {} bytes",
                                id, from_client, from_server
                            );
                        }
                        Err(e) => error!("Upgrade error: {}", e),
                    }
                });
            } else {
                // spawn a task to poll the connection and drive the HTTP state
                tokio::spawn(async move {
                    let _ = connection.await;
                });
            }

            trace!("[#{}] Request with challenge solved: {:?}", rid, fake);
            debug!("[#{}] Forwarding request to the proxy", rid);
            return req_sender
                .send_request(fake)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()));
        }

        Err(Error::new(ErrorKind::Other, "Unable to proxy"))
    }
}
