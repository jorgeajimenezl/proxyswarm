use crate::{
    core::{Address, ProxyRequest, ToStream},
    error::Error,
    proxy::{AuthenticationScheme, Proxy},
    utils::{natural_size, RequestExt, ResponseExt},
};

use base64::{engine::general_purpose::STANDARD, Engine as _};
use http_body_util::{combinators::BoxBody, BodyExt, Either, Empty};
use hyper::{
    self,
    body::{Body, Bytes, Incoming},
    client::conn::http1::{self, Connection, SendRequest},
    header, Method, Request, Response, StatusCode, Version,
};
use log::{debug, error, trace, warn};
use std::{
    future::{self, Future},
    sync::{Arc, Mutex},
    task::{ready, Poll},
};
use tokio::{
    self,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_util::sync::CancellationToken;

pub type DigestState = Option<digest_auth::WwwAuthenticateHeader>;

#[derive(Clone)]
pub struct HttpHandler {
    pub(crate) rid: u32,
    pub(crate) proxies: Vec<Proxy>,
    pub(crate) digest_state: Arc<Mutex<DigestState>>,
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

async fn tunnel<T, B1, R, S>(
    id: u32,
    connection: Connection<T, B1>,
    request: ProxyRequest<R, S>,
    cancellation_token: CancellationToken,
) -> Option<ProxyRequest<R, S>>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    R: ToStream<S> + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    B1: Body + 'static,
    <B1 as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    // Get the underlying stream and split it into the read and write halves.
    let parts = tokio::select! {
        conn = without_shutdown(connection) => {
            match conn {
                Ok(v) => v,
                Err(e) => {
                    error!("[#{id}] Unable to get underline stream: {e}");
                    return Some(request);
                }
            }
        }
        _ = cancellation_token.cancelled() => {
            return Some(request);
        }
    };

    let mut io = parts.io;

    // Upgrade the request to a tunnel.
    trace!("[#{id}] Upgrading request connection");

    let Ok(mut inner) = request.into_stream().await else {
        error!("[#{id}] Unable to get incomming stream");
        return None;
    };

    let (from, to) = match tokio::io::copy_bidirectional(&mut inner, &mut io).await {
        Ok(v) => v,
        Err(e) => {
            warn!("[#{id}] Server io error: {e}");
            return None;
        }
    };

    // Print message when done
    debug!(
        "[#{id}] Client wrote {} and received {}",
        natural_size(from, false),
        natural_size(to, false)
    );

    None
}

impl HttpHandler {
    pub fn new(
        rid: u32,
        proxies: Vec<Proxy>,
        digest_state: Arc<Mutex<Option<digest_auth::WwwAuthenticateHeader>>>,
    ) -> Self {
        HttpHandler {
            rid,
            proxies,
            digest_state,
        }
    }

    pub async fn get_proxy_transport<B>(
        &self,
        proxy: &Proxy,
    ) -> Result<(SendRequest<B>, Connection<TcpStream, B>), Error>
    where
        B: Body + 'static,
        <B as Body>::Data: Send,
        <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
    {
        // Try to connect with the proxy
        let stream = match TcpStream::connect(proxy.addr).await {
            Ok(v) => v,
            Err(e) => {
                warn!("[#{}] Proxy is unavailable: {e}", self.rid);
                return Err(e.into());
            }
        };

        let (sender, conn) = http1::handshake(stream).await?;
        Ok((sender, conn))
    }

    pub fn get_auth_response(
        &self,
        proxy: &Proxy,
        uri: &str,
        method: digest_auth::HttpMethod,
    ) -> Result<String, Error> {
        let Some(credentials) = &proxy.credentials else {
            return Err(Error::AuthenticationRequired);
        };

        // If the digest state is present, then we use it
        if let Some(state) = self.digest_state.lock().unwrap().as_mut() {
            let context = digest_auth::AuthContext::new_with_method(
                &credentials.username,
                &credentials.password,
                uri,
                Option::<&'_ [u8]>::None,
                method,
            );

            let response = state.respond(&context)?;
            Ok(response.to_header_string())
        } else {
            let cred = format!("{}:{}", credentials.username, credentials.password);
            let auth_b64 = STANDARD.encode(cred);
            Ok(format!("Basic {auth_b64}"))
        }
    }

    pub async fn request<T, S>(&self, mut req: ProxyRequest<T, S>) -> Result<(), Error>
    where
        T: ToStream<S> + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let dest = req.destination.to_string();

        for proxy in self.proxies.iter() {
            let Ok((mut sender, mut conn)) = self.get_proxy_transport::<Empty<Bytes>>(proxy).await else {
                continue;
            };

            let id = self.rid;
            let token = CancellationToken::new();
            let mut wrapper = {
                let child_token = token.clone();
                tokio::spawn(async move { tunnel(id, conn, req, child_token).await })
            };
            let mut retry_count = 3;
            let mut before = false;

            while retry_count > 0 {
                retry_count -= 1;
                let shallow = Request::builder()
                    .uri(&dest)
                    .method(Method::CONNECT)
                    .version(Version::HTTP_11)
                    .header(header::HOST, &dest)
                    // In order to make a persistent connection
                    .header("Proxy-Connection", "keep-alive")
                    .header(
                        header::USER_AGENT,
                        format!("{}/{}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION")),
                    )
                    .header(
                        header::PROXY_AUTHORIZATION,
                        self.get_auth_response(proxy, &dest, digest_auth::HttpMethod::CONNECT)?,
                    )
                    .body(Empty::new())
                    .unwrap();

                trace!("[#{id}] <Request>: {shallow:?}");
                let res = sender.send_request(shallow).await?;
                trace!("[#{id}] <Proxy Response>: {res:?}");

                if res.status().is_success() {
                    return Ok(());
                }
                if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    token.cancel();
                    return Err(Error::UnexpectedStatusCode {
                        code: res.status().as_u16(),
                        reason: res.status().canonical_reason().map(|x| x.to_string()),
                    });
                }

                let bad_creds = if let (AuthenticationScheme::Digest, Some(data)) =
                    Proxy::get_auth_info(&res)?
                {
                    let state = digest_auth::parse(data)?;
                    let r = !state.stale;
                    // Update the actual digest state
                    self.digest_state.lock().unwrap().replace(state);
                    r && before
                } else {
                    true
                };
                before = true;

                if bad_creds {
                    error!(
                        "[#{id}] Bad credentials on proxy <{}> [username={}]",
                        proxy.addr,
                        proxy.credentials.as_ref().unwrap().username
                    );
                    break;
                }

                warn!("[#{id}] Failed to authenticate. [Retry count: {retry_count}]");

                if res.is_closed() || sender.ready().await.is_err() {
                    trace!("[#{id}] Proxy closes the connection");

                    token.cancel();
                    (sender, conn) = self.get_proxy_transport(proxy).await?;
                    let id = self.rid;
                    debug!("[#{id}] Successful connected with the proxy");

                    // Re-init all
                    req = wrapper.await?.unwrap();
                    let token = CancellationToken::new();
                    wrapper = {
                        let child_token = token.clone();
                        tokio::spawn(async move { tunnel(id, conn, req, child_token).await })
                    };
                    continue;
                }

                trace!("[#{id}] Reusing old connection");
            }

            req = wrapper.await?.unwrap();
        }

        Err("Unable to proxy".into())
    }

    pub async fn request_from_http(
        &self,
        req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
        if req.method() == Method::CONNECT {
            let host = req
                .uri()
                .host()
                .map(|x| x.to_string())
                .ok_or("Invalid request, missing host part in the uri")?;

            let request = ProxyRequest {
                destination: Address::DomainAddress(host, req.uri().port_u16().unwrap_or(80)),
                inner: req,
                _phanton: std::marker::PhantomData,
            };

            let _ = self.request(request).await?;
            let empty = Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed();
            return Ok(Response::builder().body(empty).unwrap());
        }

        for proxy in self.proxies.iter() {
            let Ok((mut sender, conn)) = self.get_proxy_transport::<Either<Incoming, Empty<Bytes>>>(proxy).await else {
                continue;
            };

            let id = self.rid;
            let mut retry_count = 3;
            let mut before = false;

            tokio::spawn(async move {
                let _ = conn.await;
            });

            let path = req.uri().path().to_string();
            let method = req.method().to_string().into();

            while retry_count > 0 {
                retry_count -= 1;
                let shallow = req
                    .builder_from()
                    .method(Method::HEAD)
                    .header("Proxy-Connection", "keep-alive")
                    .header(
                        header::PROXY_AUTHORIZATION,
                        self.get_auth_response(proxy, &path, digest_auth::HttpMethod::HEAD)?,
                    )
                    .body(Either::Right(Empty::new()))
                    .unwrap();

                trace!("[#{id}] <Request>: {shallow:?}");
                let res = sender.send_request(shallow).await?;
                trace!("[#{id}] <Proxy Response>: {res:?}");

                if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    if res.is_closed() || sender.ready().await.is_err() {
                        trace!("[#{id}] Proxy closes the connection");
                        let Ok(t) = self.get_proxy_transport(proxy).await else {
                            break;
                        };
                        sender = t.0;

                        debug!("[#{id}] Connected to proxy and ready to send request");
                        tokio::spawn(async move {
                            let _ = t.1.await;
                        });
                    }

                    let mut req = req.map(Either::Left);
                    req.headers_mut().insert(
                        header::PROXY_AUTHORIZATION,
                        self.get_auth_response(proxy, &path, method)?
                            .parse()
                            .unwrap(),
                    );
                    let res = sender.send_request(req).await?;
                    return Ok(res.map(|f| f.boxed()));
                }

                let bad_creds = if let (AuthenticationScheme::Digest, Some(data)) =
                    Proxy::get_auth_info(&res)?
                {
                    let state = digest_auth::parse(data)?;
                    let r = !state.stale;
                    // Update the actual digest state
                    self.digest_state.lock().unwrap().replace(state);
                    r && before
                } else {
                    true
                };
                before = true;

                if bad_creds {
                    error!(
                        "[#{id}] Bad credentials on proxy <{}> [username={}]",
                        proxy.addr,
                        proxy.credentials.as_ref().unwrap().username
                    );
                    break;
                }

                warn!("[#{id}] Failed to authenticate. [Retry count: {retry_count}]");

                if res.is_closed() || sender.ready().await.is_err() {
                    trace!("[#{id}] Proxy closes the connection");
                    // Build a new proxy connection
                    let t = self.get_proxy_transport(proxy).await?;
                    sender = t.0;
                    debug!("[#{id}] Successful connected with the proxy");

                    // Re-init all
                    tokio::spawn(async move {
                        let _ = t.1.await;
                    });
                    continue;
                }

                trace!("[#{id}] Reusing old connection");
            }
        }

        Err("Unable to proxy".into())
    }
}
