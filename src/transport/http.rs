use super::Server;
use crate::{
    acl::Rule,
    app::AppContext,
    core::{Address, ProxyRequest},
    error::Error,
    http::HttpHandler,
};

use tokio::net::{TcpListener, TcpStream};
use tokio::{self};

use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::{
    body::{Bytes, Incoming},
    header,
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};

use async_trait::async_trait;
use log::{debug, error, info, trace, warn};

use std::net::SocketAddr;
use std::{convert::Infallible, sync::Arc};

pub struct HttpServer {
    listener: TcpListener,
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

pub async fn redirect_http(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Error> {
    debug!("Request forwarded directly to original destination");

    let host = req.uri().host().ok_or("Uri has no host")?;
    let port = req.uri().port_u16().unwrap_or(80);

    let address = format!("{port}:{host}");

    // Open a TCP connection to the remote host
    let stream = match TcpStream::connect(address).await {
        Ok(v) => v,
        Err(e) => {
            warn!("Unable to connect to {}: {e}", req.uri());
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(empty())
                .unwrap());
        }
    };

    let (mut sender, conn) = hyper::client::conn::http1::handshake(stream).await?;
    tokio::spawn(async move {
        if let Err(err) = conn.await {
            println!("Connection failed: {:?}", err);
        }
    });

    Ok(box_body!(sender.send_request(box_body!(req)).await?))
}

impl HttpServer {
    async fn handle_http_connection(
        context: AppContext,
        id: u32,
        mut req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
        debug!("[#{id}] Requested: {}", req.uri());
        trace!("[#{id}] Request struct: {req:?}");

        let Some(host) = req.uri().host().map(|x| x.to_string()) else {
            error!("[#{id}] Invalid request, missing host part in the uri");
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(empty())
                .unwrap());
        };

        match context.acl.match_hostname(&host) {
            Rule::Bypass => {
                info!("[#{id}] Bypassing connection to {host}");
                return Ok(redirect_http(req).await.unwrap_or_else(|e| {
                    error!("Error forwarding request to destination: {e}");

                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(empty())
                        .unwrap()
                }));
            }
            Rule::Deny => {
                info!("[#{id}] Deny connection to {host}");
                return Ok(Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .body(empty())
                    .unwrap());
            }
            _ => {}
        }

        // Remove proxy headers
        let headers = req.headers_mut();
        headers.remove(header::PROXY_AUTHENTICATE);
        headers.remove(header::PROXY_AUTHORIZATION);

        // Forward the request
        let client = HttpHandler::new(
            id,
            context.proxies[0].clone(),
            Arc::clone(&context.digest_state),
        );

        let req = ProxyRequest::from_request(
            Address::DomainAddress(host, req.uri().port_u16().unwrap_or(80)),
            req,
        );

        Ok(match client.request(req).await {
            Ok(res) => {
                debug!("[#{id}] Connection processed successful");
                res.map(|f| f.map(|f| f.boxed()))
                    .unwrap_or_else(|| Response::new(empty()))
            }
            Err(e) => {
                error!("Error: {e}");
                Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty())
                    .unwrap()
            }
        })
    }
}

#[async_trait]
impl Server for HttpServer {
    type StreamType = TcpStream;

    #[inline]
    async fn bind(addr: SocketAddr) -> std::io::Result<Box<Self>> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Box::new(HttpServer { listener }))
    }

    #[inline]
    async fn accept(&self) -> std::io::Result<(Self::StreamType, SocketAddr)> {
        self.listener.accept().await
    }

    #[inline]
    async fn handle_connection(
        context: AppContext,
        id: u32,
        stream: Self::StreamType,
    ) -> Result<(), Error> {
        let proxy = service_fn(move |req| Self::handle_http_connection(context.clone(), id, req));
        Ok(http1::Builder::new()
            .keep_alive(true)
            .preserve_header_case(true)
            .serve_connection(stream, proxy)
            .with_upgrades()
            .await?)
    }
}
