use super::proxy::{AuthenticationScheme, Proxy};
use super::utils::natural_size;
use crate::error::Error;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use http_body_util::Empty;
use hyper::{
    self,
    body::{Body, Bytes, Incoming},
    client::conn::http1::{self, Connection, SendRequest},
    header, Method, Request, StatusCode, Uri, Version,
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
    sync::oneshot::{self, Receiver},
};

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

async fn tunnel<T, B1, B2>(
    id: u32,
    connection: Connection<T, B1>,
    mut request: Request<B2>,
    cancellation_token: Receiver<()>,
) -> Request<B2>
where
    T: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    B1: Body + 'static,
    <B1 as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
{
    // Get the underlying stream and split it into the read and write halves.
    let parts = tokio::select! {
        conn = without_shutdown(connection) => {
            match conn {
                Ok(v) => v,
                Err(e) => {
                    error!("[#{}] Unable to get underline stream: {}", id, e);
                    return request;
                }
            }
        }
        _ = cancellation_token => {
            return request;
        }
    };

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
    uri.authority().map(|auth| auth.to_string())
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

    pub async fn get_proxy_transport(
        &self,
        proxy: &Proxy,
    ) -> Result<
        (
            SendRequest<Empty<Bytes>>,
            Connection<TcpStream, Empty<Bytes>>,
        ),
        Error,
    > {
        // Try to connect with the proxy
        let stream = match TcpStream::connect(proxy.addr).await {
            Ok(v) => v,
            Err(e) => {
                warn!("[#{}] Proxy is unavailable: {}", self.rid, e);
                return Err(e.into());
            }
        };

        let (sender, conn) = http1::handshake(stream).await?;

        Ok((sender, conn))
    }

    pub fn get_auth_response(&self, proxy: &Proxy, uri: &Uri) -> Result<String, Error> {
        let Some(credentials) = &proxy.credentials else {
            return Err(Error::AuthenticationRequired);
        };

        // If the digest state is present, then we use it
        if let Some(state) = self.digest_state.lock().unwrap().as_mut() {
            let uri = uri.to_string();
            let context = digest_auth::AuthContext::new_with_method(
                &credentials.username,
                &credentials.password,
                &uri,
                Option::<&'_ [u8]>::None,
                digest_auth::HttpMethod::CONNECT,
            );

            let response = state.respond(&context)?;
            Ok(response.to_header_string())
        } else {
            let cred = format!("{}:{}", credentials.username, credentials.password);
            let auth_b64 = STANDARD.encode(cred);
            Ok(format!("Basic {auth_b64}"))
        }
    }

    pub async fn request(&self, mut req: Request<Incoming>) -> Result<(), Error> {
        let uri = req.uri().clone();

        for proxy in self.proxies.iter() {
            let Ok((mut sender, conn)) = self.get_proxy_transport(proxy).await else {
                continue;
            };

            let id = self.rid;
            let (mut tx, mut rx) = oneshot::channel();
            let mut wrapper = tokio::spawn(async move { tunnel(id, conn, req, rx).await });
            let mut retry_count = 3;
            let mut before = false;

            while retry_count > 0 {
                retry_count -= 1;
                let shallow = Request::builder()
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
                    .header(
                        header::PROXY_AUTHORIZATION,
                        self.get_auth_response(proxy, &uri)?,
                    )
                    .body(Empty::new())
                    .unwrap();

                trace!("[#{}] <Request>: {:?}", self.rid, shallow);
                let res = sender.send_request(shallow).await?;
                trace!("[#{}] <Proxy Response>: {:?}", self.rid, res);

                if res.status().is_success() {
                    return Ok(());
                }
                if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                    tx.send(()).unwrap();
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
                        "[#{}] Bad credentials on proxy <{}> [username={}]",
                        self.rid,
                        proxy.addr,
                        proxy.credentials.as_ref().unwrap().username
                    );
                    break;
                }

                warn!(
                    "[#{}] Failed to authenticate. [Retry count: {}]",
                    self.rid, retry_count
                );

                let closed = match res.headers().get(header::CONNECTION) {
                    Some(conn_header) => conn_header.to_str()?.eq_ignore_ascii_case("close"),
                    None => false,
                };

                if closed
                    || matches!(res.version(), Version::HTTP_10)
                    || sender.ready().await.is_err()
                {
                    trace!("[#{}] Proxy closes the connection", self.rid);

                    // Send token to cancel wait
                    tx.send(()).unwrap();

                    // Build a new proxy connection
                    let t = self.get_proxy_transport(proxy).await?;
                    sender = t.0;
                    let id = self.rid;

                    debug!("[#{}] Successful connected with the proxy", self.rid);

                    // Re-init all
                    req = wrapper.await?;
                    (tx, rx) = oneshot::channel();
                    wrapper = tokio::spawn(async move { tunnel(id, t.1, req, rx).await });
                    continue;
                }

                trace!("[#{}] Reusing old connection", self.rid);
            }

            req = wrapper.await?;
        }

        Err("Unable to proxy".into())
    }
}
