// WARNING: IMPLEMENT POOL
use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::{
    self,
    body::{Body, Bytes, Incoming},
    client::conn::http1::{self, Connection, SendRequest},
    header, Method, Request, Response, StatusCode, Uri, Version,
};
use log::{debug, error, trace, warn};
use std::{
    future::{self, Future},
    io::{Error, ErrorKind},
    task::{ready, Poll},
};
use tokio::{
    self,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::oneshot::{self, Receiver},
};

#[derive(Clone)]
pub struct ProxyHttp {
    pub(crate) rid: u32,
    pub(crate) proxies: Vec<Proxy>,
    pub(crate) bypass: Vec<String>,
}

use super::proxy::{Proxy, ProxyAuthentication};
use super::utils::natural_size;

#[inline]
pub(crate) fn io_err<E: Into<Box<dyn std::error::Error + Send + Sync>>>(e: E) -> Error {
    Error::new(ErrorKind::Other, e)
}

macro_rules! box_body {
    ($t:expr) => {
        $t.map(|f| f.boxed())
    };
}

#[inline]
pub(crate) fn empty() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new()
        .map_err(|never| match never {})
        .boxed()
}

async fn create_stream(uri: &Uri) -> Result<TcpStream, Error> {
    let host = uri
        .host()
        .ok_or(Error::new(ErrorKind::InvalidInput, "Uri has no host"))?;
    let port = uri.port_u16().unwrap_or(80);

    let address = format!("{}:{}", host, port);

    // Open a TCP connection to the remote host
    return Ok(TcpStream::connect(address).await?);
}

pub fn without_shutdown<T, B>(
    conn: Connection<T, B>,
) -> impl Future<Output = hyper::Result<http1::Parts<T>>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B: Body + 'static,
    <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    let mut conn = Some(conn);
    future::poll_fn(move |cx| -> Poll<hyper::Result<http1::Parts<T>>> {
        ready!(conn.as_mut().unwrap().poll_without_shutdown(cx))?;
        Poll::Ready(Ok(conn.take().unwrap().into_parts()))
    })
}

async fn tunnel<T, B1, B2>(
    id: u32,
    connection: Connection<T, B1>,
    mut request: Request<B2>,
    status: Receiver<bool>,
) -> Request<B2>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B1: Body + 'static,
    <B1 as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    // Get the underlying stream and split it into the read and write halves.
    let parts = match without_shutdown(connection).await {
        Ok(v) => v,
        Err(e) => {
            error!("[#{}] Unable to get underline stream: {}", id, e);
            return request;
        }
    };

    match status.await {
        Ok(true) => {}
        _ => {
            return request;
        }
    }

    let mut io = parts.io;

    // Upgrade the request to a tunnel.
    trace!("[#{}] Upgrading request connection", id);

    match hyper::upgrade::on(&mut request).await {
        Ok(mut upgraded) => {
            // Proxying data
            let (from, to) = match tokio::io::copy_bidirectional(&mut upgraded, &mut io).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("[#{}] Server io error: {}", id, e);
                    return request;
                }
            };

            // Print message when done
            debug!(
                "[#{}] Client wrote {} and received {}",
                id,
                natural_size(from, false),
                natural_size(to, false)
            );
        }
        Err(e) => warn!("[#{}] Upgrade error: {}", id, e),
    }

    request
}

fn host_addr(uri: &Uri) -> Option<String> {
    uri.authority().and_then(|auth| Some(auth.to_string()))
}

impl ProxyHttp {
    pub fn new(rid: u32, proxies: Vec<Proxy>, bypass: Vec<String>) -> Self {
        ProxyHttp {
            rid,
            proxies,
            bypass,
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

    pub async fn baypass_direct(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        debug!(
            "[#{}] Request forwarded directly to original destination",
            self.rid
        );

        let stream = match create_stream(req.uri()).await {
            Ok(v) => v,
            Err(e) => {
                warn!("Unable to connect to {}: {}", req.uri(), e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty())
                    .unwrap());
            }
        };

        let (mut sender, conn) = http1::handshake(stream)
            .await
            .map_err(|e| io_err::<hyper::Error>(e.into()))?;
        tokio::spawn(async move {
            if let Err(err) = conn.await {
                println!("Connection failed: {:?}", err);
            }
        });

        return Ok(box_body!(sender
            .send_request(box_body!(req))
            .await
            .map_err(|e| io_err::<hyper::Error>(e.into()))?));
    }

    pub async fn discover_proxy_scheme(
        &self,
        uri: &Uri,
        sender: &mut SendRequest<Empty<Bytes>>,
    ) -> Result<ProxyAuthentication, Error> {
        let req = Request::builder()
            .uri(uri)
            .method(Method::CONNECT)
            .version(Version::HTTP_11)
            .header(
                header::HOST,
                host_addr(uri).ok_or(Error::new(
                    ErrorKind::Other,
                    "Unable to get authority section in the request uri",
                ))?,
            )
            .body(Empty::new())
            .unwrap();

        trace!("[#{}] <Request>: {:?}", self.rid, req);
        debug!("[#{}] Discovering the proxy auth scheme", self.rid);

        let res = sender
            .send_request(req)
            .await
            .map_err(|e| io_err::<hyper::Error>(e.into()))?;

        trace!("[#{}] <Proxy response>: {:?}", self.rid, res);

        if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
            return Ok(ProxyAuthentication::None);
        }

        Ok(
            Proxy::get_auth_info(&res)
                .map_err(|e| io_err::<hyper::header::ToStrError>(e.into()))?,
        )
    }

    pub async fn get_transport(
        &self,
        uri: &Uri,
    ) -> Result<
        (
            SendRequest<Empty<Bytes>>,
            Connection<TcpStream, Empty<Bytes>>,
        ),
        Error,
    > {
        // Try to connect with the proxy
        let stream = match create_stream(uri).await {
            Ok(v) => v,
            Err(e) => {
                warn!("[#{}] Proxy {} is unavailable: {}", self.rid, uri, e);
                return Err(e);
            }
        };

        let (sender, conn) = http1::handshake(stream)
            .await
            .map_err(|e| io_err::<hyper::Error>(e.into()))?;

        return Ok((sender, conn));
    }

    pub async fn request(
        &self,
        mut req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        let (uri, _method, _version) = (
            req.uri().clone(),
            req.method().clone(),
            req.version().clone(),
        );

        {
            let host = &uri.host().unwrap_or_default().to_string();
            if self.bypass.contains(host) {
                return self.baypass_direct(req).await;
            }
        }

        for proxy in self.proxies.iter() {
            let Ok((mut sender, conn)) = self.get_transport(&proxy.uri).await else {
                continue;
            };

            let id = self.rid;
            let (mut tx, mut rx) = oneshot::channel();
            // Spawn a task to poll the connection and drive the HTTP state
            let mut wrapper = tokio::spawn(async move { tunnel(id, conn, req, rx).await });
            let mut auth_info = self.discover_proxy_scheme(&uri, &mut sender).await?;

            trace!(
                "[#{}] Authentication scheme information: {:?}",
                self.rid,
                auth_info
            );

            if auth_info == ProxyAuthentication::None {
                trace!("[#{}] Proxy don't require authentication", self.rid);
                // TODO: forward all the content
                todo!();
            }

            debug!("[#{}] Proxy require authentication", self.rid);

            let mut retry_count = 3;

            while retry_count > 0 {
                match sender.ready().await {
                    Ok(_) => {
                        debug!("[#{}] Reusing old connection", self.rid);
                    }
                    Err(_) => {
                        trace!("[#{}] Proxy closes the connection", self.rid);
                        tx.send(false).unwrap();

                        // Recovery the req instance
                        req = wrapper.await?;

                        // Build a new proxy connection
                        let t = self.get_transport(&proxy.uri).await?;
                        sender = t.0;
                        let id = self.rid;

                        debug!("[#{}] Successful connected with the proxy", self.rid);

                        // Spawn a task to poll the connection and drive the HTTP state
                        (tx, rx) = oneshot::channel();
                        wrapper = tokio::spawn(async move { tunnel(id, t.1, req, rx).await });
                    }
                }

                // Create the proxy "real" request
                let mut req = Request::builder()
                    .uri(&uri)
                    .method(Method::CONNECT)
                    .version(Version::HTTP_11)
                    .header(header::HOST, host_addr(&uri).unwrap())
                    // In order to make a persistent connection
                    .header("Proxy-Connection", "keep-alive")
                    .header(
                        header::USER_AGENT,
                        format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                    )
                    .body(Empty::new())
                    .unwrap();

                // Add proxy authorization headers
                if auth_info != ProxyAuthentication::None {
                    proxy.add_authentication_headers(&mut auth_info, &mut req)?;
                }

                trace!("[#{}] <Request with challenge solved>: {:?}", self.rid, req);

                let res = sender
                    .send_request(req)
                    .await
                    .map_err(|e| io_err::<hyper::Error>(e.into()))?;

                trace!("[#{}] <Proxy Response>: {:?}", self.rid, res);

                if res.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    // Check for bad credentials
                    let bad = if let ProxyAuthentication::Digest(_) = auth_info {
                        if let ProxyAuthentication::Digest(i) = Proxy::get_auth_info(&res)
                            .map_err(|e| io_err::<hyper::header::ToStrError>(e.into()))?
                        {
                            let r = i.stale == false;
                            auth_info = ProxyAuthentication::Digest(i);
                            r
                        } else {
                            error!(
                                "[#{}] Proxy ask for two different schemes in two on row requests",
                                self.rid
                            );
                            break;
                        }
                    } else {
                        true
                    };

                    if bad {
                        error!(
                            "[#{}] Bad credentials on proxy <{}> [username={}]",
                            self.rid,
                            proxy.uri,
                            proxy.credentials.as_ref().unwrap().username
                        );
                        break;
                    }

                    warn!(
                        "[#{}] Failed to authenticate. [Retry count: {}]",
                        self.rid, retry_count
                    );
                    retry_count -= 1;
                    continue;
                }

                tx.send(true).unwrap();

                // tx.send(true).unwrap();
                return Ok(box_body!(res));
            }

            req = wrapper.await?;
        }

        Err(Error::new(ErrorKind::Other, "Unable to proxy"))
    }
}
