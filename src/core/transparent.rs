use super::client::{io_err, ProxyClient};
use super::proxy::{add_authentication_headers, get_proxy_auth_info, ProxyAuthentication};
use super::utils::{natural_size, set_socket_mark};

use hyper::{
    self,
    client::conn::{Builder, Connection},
    header::{HOST, PROXY_AUTHENTICATE},
    service::Service,
    Body, Method, Request, StatusCode, Version,
};
use hyper_tls::{HttpsConnector, MaybeHttpsStream};
use tokio::io::{AsyncRead, AsyncWrite};

use std::io::{Error, ErrorKind};
use tokio::net::TcpStream;

use log::{debug, error, trace, warn};

async fn tunnel<T>(id: u32, connection: Connection<T, Body>, stream: &mut TcpStream)
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

    let (from, to) = match tokio::io::copy_bidirectional(stream, &mut io).await {
        Ok(v) => v,
        Err(e) => {
            warn!("[#{}] Server io error: {}", id, e);
            return;
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

impl ProxyClient {
    pub async fn request_transparent(
        &self,
        mut stream: TcpStream,
        destination: &str,
    ) -> Result<(), Error> {
        for host in self.bypass.iter() {
            if destination != host {
                continue;
            }
            let mut client = TcpStream::connect(destination).await?;
            let (from, to) = tokio::io::copy_bidirectional(&mut stream, &mut client).await?;

            debug!(
                "[#{}] Client wrote {} and received {}",
                self.rid,
                natural_size(from, false),
                natural_size(to, false)
            );
            return Ok(());
        }

        let mut connector = HttpsConnector::new();

        for proxy in self.proxies.iter() {
            // Create a ping request to ask to the proxy the authentication scheme
            let req = Request::builder()
                .uri(destination)
                .method(Method::CONNECT)
                .version(Version::HTTP_11) // FIX: Compatibility issues
                .header(HOST, destination)
                .body(Body::empty())
                .unwrap();

            let out = match connector.call(proxy.uri.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    warn!("[#{}] Proxy {} is unavailable: {}", self.rid, proxy.uri, e);
                    continue;
                }
            };

            // Set the socket mark
            match &out {
                MaybeHttpsStream::Http(s) => set_socket_mark(s, 0x1234)?,
                MaybeHttpsStream::Https(s) => set_socket_mark(s, 0x1234)?,
            };

            let (mut req_sender, connection) = Builder::new()
                .handshake::<MaybeHttpsStream<TcpStream>, Body>(out)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            // Spawn a task to poll the connection and drive the HTTP state
            tokio::spawn(async move {
                let _ = connection.await;
            });

            trace!("[#{}] Request: {:?}", self.rid, req);
            debug!("[#{}] Forwarding request to the proxy", self.rid);
            let res = req_sender
                .send_request(req)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            // If proxy don't say 407 just redirect the request
            if res.status() != StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                trace!("[#{}] Proxy don't require authentication", self.rid);
                return Ok(());
            }
            debug!("[#{}] Proxy require authentication", self.rid);

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

            let out = match connector.call(proxy.uri.clone()).await {
                Ok(v) => v,
                Err(e) => {
                    warn!(
                        "[#{}] Proxy {} is unavailable to resolve authentication challenge: {}",
                        self.rid, proxy.uri, e
                    );
                    continue;
                }
            };

            // Set the socket mark
            match &out {
                MaybeHttpsStream::Http(s) => set_socket_mark(s, 0x1234)?,
                MaybeHttpsStream::Https(s) => set_socket_mark(s, 0x1234)?,
            };

            let (mut req_sender, connection) = Builder::new()
                .handshake::<MaybeHttpsStream<TcpStream>, Body>(out)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            {
                let id = self.rid;
                tokio::spawn(async move {
                    tunnel(id, connection, &mut stream).await;
                });
            }

            let mut req = Request::builder()
                .uri(destination)
                .method(Method::CONNECT)
                .version(Version::HTTP_11) // FIX: Compatibility issues
                .header(HOST, destination)
                .body(Body::empty())
                .unwrap();

            // Add proxy authorization headers
            if auth_info != ProxyAuthentication::None {
                add_authentication_headers(
                    auth_info,
                    proxy.credentials.clone().ok_or(Error::new(
                        ErrorKind::Other,
                        "The proxy require credentials and it not was given",
                    ))?,
                    &mut req,
                );
            }

            trace!("[#{}] Request with challenge solved: {:?}", self.rid, req);
            debug!("[#{}] Forwarding request to the proxy", self.rid);
            let _ = req_sender
                .send_request(req)
                .await
                .map_err(|e| io_err::<hyper::Error>(e.into()))?;

            return Ok(());
        }

        Ok(())
    }
}
