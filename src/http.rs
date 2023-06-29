use crate::core::{ProxyRequest, ToStream};
use crate::error::Error;
use crate::proxy::{AuthenticationScheme, Proxy};
use crate::utils::natural_size;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use http_body_util::Empty;
use hyper::{
    self,
    body::{Body, Bytes},
    client::conn::http1::{self, Connection, SendRequest},
    header, Method, Request, StatusCode, Version,
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

async fn tunnel<T, B1, R, S>(
    id: u32,
    connection: Connection<T, B1>,
    request: ProxyRequest<R, S>,
    cancellation_token: Receiver<()>,
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
        _ = cancellation_token => {
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
                warn!("[#{}] Proxy is unavailable: {e}", self.rid);
                return Err(e.into());
            }
        };

        let (sender, conn) = http1::handshake(stream).await?;

        Ok((sender, conn))
    }

    pub fn get_auth_response(&self, proxy: &Proxy, uri: &str) -> Result<String, Error> {
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

    pub async fn request<T, S>(&self, mut req: ProxyRequest<T, S>) -> Result<(), Error>
    where
        T: ToStream<S> + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let dest = req.destination.to_string();

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
                        self.get_auth_response(proxy, &dest)?,
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
                        "[#{id}] Bad credentials on proxy <{}> [username={}]",
                        proxy.addr,
                        proxy.credentials.as_ref().unwrap().username
                    );
                    break;
                }

                warn!("[#{id}] Failed to authenticate. [Retry count: {retry_count}]");

                let closed = match res.headers().get(header::CONNECTION) {
                    Some(conn_header) => conn_header.to_str()?.eq_ignore_ascii_case("close"),
                    None => false,
                };

                if closed
                    || matches!(res.version(), Version::HTTP_10)
                    || sender.ready().await.is_err()
                {
                    trace!("[#{id}] Proxy closes the connection");

                    // Send token to cancel wait
                    tx.send(()).unwrap();

                    // Build a new proxy connection
                    let t = self.get_proxy_transport(proxy).await?;
                    sender = t.0;
                    let id = self.rid;

                    debug!("[#{id}] Successful connected with the proxy");

                    // Re-init all
                    req = wrapper.await?.unwrap();
                    (tx, rx) = oneshot::channel();
                    wrapper = tokio::spawn(async move { tunnel(id, t.1, req, rx).await });
                    continue;
                }

                trace!("[#{id}] Reusing old connection");
            }

            req = wrapper.await?.unwrap();
        }

        Err("Unable to proxy".into())
    }
}
