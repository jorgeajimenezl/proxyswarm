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
    client::conn::http1::{self, SendRequest},
    header, Method, Request, Response, StatusCode, Version,
};
use log::{debug, error, trace, warn};
use std::sync::{Arc, Mutex};
use tokio::{
    self,
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

pub type DigestState = Option<digest_auth::WwwAuthenticateHeader>;

#[derive(Clone)]
pub struct HttpHandler {
    pub(crate) rid: u32,
    pub(crate) proxy: Proxy,
    pub(crate) digest_state: Arc<Mutex<DigestState>>,
}

async fn tunnel<T, S, B>(id: u32, req: ProxyRequest<T, S>, res: Response<B>)
where
    T: ToStream<S> + Send + Unpin + 'static,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    match hyper::upgrade::on(res).await {
        Ok(mut upgraded) => {
            let Ok(mut inner) = req.into_stream().await else {
                error!("[#{id}] Unable to get incomming stream");
                return;
            };

            let (from, to) = match tokio::io::copy_bidirectional(&mut inner, &mut upgraded).await {
                Ok(v) => v,
                Err(_e) => {
                    // warn!("[#{id}] Server io error: {e}");
                    return;
                }
            };

            // Print message when done
            debug!(
                "[#{id}] Client wrote {} and received {}",
                natural_size(from, false),
                natural_size(to, false)
            );
        }
        Err(e) => eprintln!("upgrade error: {}", e),
    }
}

impl HttpHandler {
    pub fn new(
        rid: u32,
        proxy: Proxy,
        digest_state: Arc<Mutex<Option<digest_auth::WwwAuthenticateHeader>>>,
    ) -> Self {
        HttpHandler {
            rid,
            proxy,
            digest_state,
        }
    }

    pub async fn get_proxy_transport<B>(&self) -> Result<SendRequest<B>, Error>
    where
        B: Body + Send + 'static,
        <B as Body>::Data: Send,
        <B as Body>::Error: Into<Box<(dyn std::error::Error + Send + Sync + 'static)>>,
    {
        // Try to connect with the proxy
        let stream = match TcpStream::connect(self.proxy.addr).await {
            Ok(v) => v,
            Err(e) => {
                warn!("[#{}] Proxy is unavailable: {e}", self.rid);
                return Err(e.into());
            }
        };

        let (sender, conn) = http1::handshake(stream).await?;
        tokio::spawn(async move {
            let _ = conn.await;
        });
        debug!("[#{}] Successful connected with the proxy", self.rid);
        Ok(sender)
    }

    pub fn get_auth_response(
        &self,
        uri: &str,
        method: digest_auth::HttpMethod,
    ) -> Result<String, Error> {
        let Some(credentials) = &self.proxy.credentials else {
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

    pub async fn request<T, S>(&self, req: ProxyRequest<T, S>) -> Result<(), Error>
    where
        T: ToStream<S> + Send + Unpin + 'static,
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let id = self.rid;
        let dest = req.destination.to_string();
        let mut sender = self.get_proxy_transport::<Empty<Bytes>>().await?;
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
                    self.get_auth_response(&dest, digest_auth::HttpMethod::CONNECT)?,
                )
                .body(Empty::new())
                .unwrap();

            trace!("[#{id}] <Request>: {shallow:?}");
            let res = sender.send_request(shallow).await?;
            trace!("[#{id}] <Proxy Response>: {res:?}");

            if res.status().is_success() {
                tokio::spawn(async move { tunnel(id, req, res).await });
                return Ok(());
            }
            if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                return Err(Error::UnexpectedStatusCode {
                    code: res.status().as_u16(),
                    reason: res.status().canonical_reason().map(|x| x.to_string()),
                });
            }

            let bad_creds =
                if let (AuthenticationScheme::Digest, Some(data)) = Proxy::get_auth_info(&res)? {
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
                    "[#{id}] Bad credentials on proxy <{}> [{}]",
                    self.proxy.addr,
                    self.proxy.credentials.as_ref().unwrap().username
                );
                break;
            }

            warn!("[#{id}] Failed to authenticate. [Retry count: {retry_count}]");

            if res.is_closed() || sender.ready().await.is_err() {
                trace!("[#{id}] Proxy closes the connection");
                sender = self.get_proxy_transport().await?;
                continue;
            }

            trace!("[#{id}] Reusing old connection");
        }
        Err("Unable to proxify".into())
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

            self.request(request).await?;
            let empty = Empty::<Bytes>::new()
                .map_err(|never| match never {})
                .boxed();
            return Ok(Response::new(empty));
        }

        let mut sender = self
            .get_proxy_transport::<Either<Incoming, Empty<Bytes>>>()
            .await?;
        let id = self.rid;
        let mut retry_count = 3;
        let mut before = false;
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
                    self.get_auth_response(&path, digest_auth::HttpMethod::HEAD)?,
                )
                .body(Either::Right(Empty::new()))
                .unwrap();

            trace!("[#{id}] <Request>: {shallow:?}");
            let res = sender.send_request(shallow).await?;
            trace!("[#{id}] <Proxy Response>: {res:?}");

            if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                if res.is_closed() || sender.ready().await.is_err() {
                    trace!("[#{id}] Proxy closes the connection");
                    sender = self.get_proxy_transport().await?;
                }

                let mut req = req.map(Either::Left);
                req.headers_mut().insert(
                    header::PROXY_AUTHORIZATION,
                    self.get_auth_response(&path, method)?.parse().unwrap(),
                );
                let res = sender.send_request(req).await?;
                return Ok(res.map(|f| f.boxed()));
            }

            let bad_creds =
                if let (AuthenticationScheme::Digest, Some(data)) = Proxy::get_auth_info(&res)? {
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
                    self.proxy.addr,
                    self.proxy.credentials.as_ref().unwrap().username
                );
                break;
            }

            warn!("[#{id}] Failed to authenticate. [Retry count: {retry_count}]");

            if res.is_closed() || sender.ready().await.is_err() {
                trace!("[#{id}] Proxy closes the connection");
                sender = self.get_proxy_transport().await?;
                continue;
            }

            trace!("[#{id}] Reusing old connection");
        }

        Err("Unable to proxy".into())
    }
}
