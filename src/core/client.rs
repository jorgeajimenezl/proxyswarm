// WARNING: IMPLEMENT POOL
use hyper::{
    self,
    client::{
        conn::{Builder, Connection},
        // connect::HttpConnector,
        Client,
    },
    header::{HOST, PROXY_AUTHENTICATE},
    service::Service,
    Body, Method, Request, Response, StatusCode,
};
use hyper_tls::{HttpsConnector, MaybeHttpsStream};
use log::{debug, error, trace, warn};
use std::io::{Error, ErrorKind};
use tokio::{self, io::{AsyncRead, AsyncWrite}, net::TcpStream};

#[derive(Clone)]
pub struct ProxyClient {
    proxies: Vec<Proxy>,
    bypass: Vec<String>,
}

use super::utils::natural_size;
use super::proxy::{add_authentication_headers, get_proxy_auth_info, Proxy, ProxyAuthentication};

#[inline]
fn io_err<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> Error {
    Error::new(ErrorKind::Other, e)
}

async fn tunnel<T>(id: u32, connection: Connection<T, Body>, req: Request<Body>)
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
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
                        warn!("[#{}] Server io error: {}", id, e);
                        return;
                    }
                };

            // Print message when done
            debug!(
                "[#{}] Client wrote {} and received {}",
                id, natural_size(from_client, false), natural_size(from_server, false)
            );
        }
        Err(e) => warn!("Upgrade error: {}", e),
    }
}

impl ProxyClient {
    // pub fn new() -> Self {
    //     ProxyClient {
    //         proxies: Vec::new(),
    //         bypass: Vec::new()
    //     }
    // }

    pub fn from_parts(proxies: Vec<Proxy>, bypass: Vec<String>) -> Self {
        ProxyClient {
            proxies: proxies,
            bypass: bypass,
        }
    }

    // pub fn from_proxy(proxy: Proxy) -> Self {
    //     ProxyClient {
    //         proxies: vec![proxy],
    //         bypass: Vec::new()
    //     }
    // }

    // pub fn add_bypass_uri(&mut self, uri: &str) {
    //     self.bypass.push(String::from(uri));
    // }

    // pub fn add_proxy(&mut self, proxy: Proxy) {
    //     self.proxies.push(proxy);
    // }

    // pub fn proxies(&self) -> &[Proxy] {
    //     return &self.proxies;
    // }

    pub async fn request(&self, rid: u32, req: Request<Body>) -> Result<Response<Body>, Error> {
        let mut connector = HttpsConnector::new();

        for host in self.bypass.iter() {
            if req.uri().host().unwrap_or_default() == host {
                // TODO: FIX THIS
                debug!(
                    "[#{}] Request forwarded directly to original destination",
                    rid
                );

                if req.method() != Method::CONNECT {
                    return Client::builder()
                        .build::<_, Body>(connector)
                        .request(req)
                        .await
                        .map_err(|e| io_err::<hyper::Error>(e.into()));
                } else {
                    let mut stream = match connector.call(req.uri().clone()).await {
                        Ok(v) => v,
                        Err(e) => {
                            warn!("Unable to connect to {}: {}", req.uri(), e);
                            return Ok(Response::builder()
                                .status(StatusCode::BAD_GATEWAY)
                                .body(Body::empty())
                                .unwrap());
                        }
                    };

                    let id = rid;
                    tokio::spawn(async move {
                        match hyper::upgrade::on(req).await {
                            Ok(mut upgraded) => {
                                let (from_client, from_server) =
                                    match tokio::io::copy_bidirectional(&mut upgraded, &mut stream)
                                        .await
                                    {
                                        Ok(v) => v,
                                        Err(e) => {
                                            warn!("[#{}] Server io error: {}", id, e);
                                            return;
                                        }
                                    };

                                // Print message when done
                                debug!(
                                    "[#{}] Client wrote {} bytes and received {} bytes",
                                    id, from_client, from_server
                                );
                            }
                            Err(e) => warn!("Upgrade error: {}", e),
                        }
                    });

                    return Ok(Response::new(Body::empty()));
                }
            }
        }

        for proxy in self.proxies.iter() {
            let stream = match connector.call(proxy.uri.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("[#{}] Proxy {} is unavailable: {}", rid, proxy.uri, e);
                    continue;
                }
            };

            // Create a ping request to ask to the proxy the authentication scheme
            let ping = Request::builder()
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
                        "Unable to get authority section in the request uri",
                    ))?,
                )
                .body(Body::empty())
                .unwrap();

            let (mut req_sender, connection) = Builder::new()
                .handshake::<MaybeHttpsStream<TcpStream>, Body>(stream)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            // Spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                let _ = connection.await;
            });

            trace!("[#{}] Request: {:?}", rid, ping);
            debug!("[#{}] Forwarding request to the proxy", rid);
            let res = req_sender
                .send_request(ping)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            // If proxy don't say 407 just redirect the request
            if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                trace!("[#{}] Proxy don't require authentication", rid);
                return Ok(res);
            }
            debug!("[#{}] Proxy require authentication", rid,);

            let headers = res.headers();
            let auth_info = get_proxy_auth_info(match headers.get(PROXY_AUTHENTICATE) {
                Some(d) => d
                    .to_str()
                    .map_err(|e| io_err::<hyper::header::ToStrError>(e.into()))?,
                None => {
                    return Err(Error::new(
                        ErrorKind::Other,
                        "Unable to get authentication scheme from proxy",
                    ));
                }
            });

            trace!("Authentication scheme information: {:?}", auth_info);

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
                .handshake::<MaybeHttpsStream<TcpStream>, Body>(stream)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            let mut forward: Request<Body>;

            if req.method() == Method::CONNECT {
                let id = rid;
                // Create new request (CONNECT request must no have headers)
                forward = Request::builder()
                    .uri(req.uri())
                    .method(req.method())
                    .version(req.version())
                    .header(HOST, req.uri().authority().map(|a| a.as_str()).unwrap())
                    .body(Body::empty())
                    .unwrap();

                // Spawn a task to poll the request and upgrade to make the tunnel
                tokio::spawn(async move {
                    tunnel(id, connection, req).await;
                });
            } else {
                // spawn a task to poll the connection and drive the HTTP state
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                forward = req;
            }

            // Add proxy authorization headers
            if auth_info != ProxyAuthentication::None {
                add_authentication_headers(
                    auth_info,
                    proxy.credentials.clone().ok_or(Error::new(
                        ErrorKind::Other,
                        "The proxy require credentials and it not was given",
                    ))?,
                    &mut forward,
                );
            }

            trace!("[#{}] Request with challenge solved: {:?}", rid, forward);
            debug!("[#{}] Forwarding request to the proxy", rid);
            return req_sender
                .send_request(forward)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()));
        }

        Err(Error::new(ErrorKind::Other, "Unable to proxy"))
    }
}
