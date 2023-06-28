use super::http::{DigestState, HttpHandler};
use super::proxy::{Credentials, Proxy};
use crate::acl::{Acl, Rule};
use crate::error::Error;

use tokio::net::{TcpListener, TcpStream};
use tokio::{self, signal, sync::oneshot};

use http_body_util::{combinators::BoxBody, BodyExt, Empty};
use hyper::{
    body::{Bytes, Incoming},
    header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};

use config::Config;
use log::{debug, error, info, trace, warn};

use std::{
    convert::Infallible,
    net::SocketAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc, Mutex,
    },
};

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

#[derive(Clone, Debug)]
pub enum OperationMode {
    Transparent,
    Proxy,
}

impl FromStr for OperationMode {
    type Err = String;
    fn from_str(x: &str) -> Result<Self, <Self as std::str::FromStr>::Err> {
        let x = x.to_lowercase();
        match x.as_ref() {
            "proxy" => Ok(OperationMode::Proxy),
            "transparent" => Ok(OperationMode::Transparent),
            _ => Err(String::from("Proxy mode not available")),
        }
    }
}

#[derive(Clone)]
pub struct AppContext {
    pub addr: SocketAddr,
    pub proxies: Vec<Proxy>,
    pub mode: OperationMode,
    pub acl: Acl,

    digest_state: Arc<Mutex<DigestState>>,
}

pub struct App {
    context: AppContext,
}

impl App {
    fn build_appcontext(config: Config) -> Result<AppContext, Error> {
        let mut proxies = Vec::new();
        let mut acl = Acl::new(Rule::Allow);

        for value in config
            .get_array("general.bypass")
            .unwrap_or(vec!["127.0.0.1/8".into()])
        {
            // bypass.push(value.into_string()?);
            acl.add(&value.to_string(), Rule::Deny)?;
        }

        let mode = config
            .get_string("general.mode")
            .unwrap_or(String::from("proxy"))
            .parse::<OperationMode>()?;

        // Get the proxies
        let proxy = {
            let username = match config.get("proxy.username") {
                Ok(v) => Some(v),
                Err(e) => match e {
                    config::ConfigError::NotFound(_) => None,
                    _ => return Err(e.into()),
                },
            };
            let password = match config.get("proxy.password") {
                Ok(v) => Some(v),
                Err(e) => match e {
                    config::ConfigError::NotFound(_) => None,
                    _ => return Err(e.into()),
                },
            };
            let uri = config.get_string("proxy.uri")?;

            if (username.is_some() && password.is_none())
                || (username.is_none() && password.is_some())
            {
                return Err(String::from(
                    "The proxy session must include username and password or neither",
                )
                .into());
            }

            let mut res = Proxy::from_str(&uri)?;
            // overwrite the user pass
            res.credentials = res.credentials.or(username.map(|username| Credentials {
                username,
                password: password.unwrap(),
            }));
            res
        };

        proxies.push(proxy);

        let listen_addr: SocketAddr = config
            .get_string("general.bind-address")
            .unwrap_or(String::from("0.0.0.0:8081"))
            .parse()
            .map_err(|e| format!("{e}"))?;

        Ok(AppContext {
            addr: listen_addr,
            mode,
            proxies,
            acl,
            digest_state: Default::default(),
        })
    }

    pub fn from_config(config: Config) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        Ok(App {
            context: App::build_appcontext(config)?,
        })
    }

    async fn handle_connection(
        context: AppContext,
        id: u32,
        mut req: Request<Incoming>,
    ) -> Result<Response<BoxBody<Bytes, hyper::Error>>, Infallible> {
        debug!("[#{id}] Requested: {}", req.uri());
        trace!("[#{id}] Request struct: {req:?}");

        if let Some(host) = req.uri().host() {
            if context.acl.match_hostname(host) == Rule::Deny {
                debug!("[#{id}] Avoided try to connect with {host}");
                return Ok(redirect_http(req).await.unwrap_or_else(|e| {
                    error!("Error forwarding request to destination: {e}");

                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(empty())
                        .unwrap()
                }));
            }
        }

        // Remove proxy headers
        if matches!(context.mode, OperationMode::Proxy) {
            let headers = req.headers_mut();
            headers.remove(PROXY_AUTHENTICATE);
            headers.remove(PROXY_AUTHORIZATION);
        }

        // Forward the request
        let client = HttpHandler::new(id, context.proxies, Arc::clone(&context.digest_state));
        if let Err(e) = client.request(req).await {
            error!("Error forwarding request to destination: {e}");
            return Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(empty())
                .unwrap());
        }

        debug!("[#{id}] Connection processed successful");
        Ok(Response::builder().body(empty()).unwrap())
    }

    async fn serve_http(context: AppContext) -> Result<(), Error> {
        let addr = context.addr;
        let count = Arc::new(AtomicU32::new(0));

        let tcp_listener = TcpListener::bind(addr).await?;
        info!("Proxy listening at http://{addr}. Press Ctrl+C to stop it",);

        let (tx, mut rx) = oneshot::channel();

        // Main loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    conn = tcp_listener.accept() => {
                        let (stream, remote_addr) = match conn {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Unable to accept incomming TCP connection: {e}");
                                return;
                            }
                        };

                        // Get connections count
                        let id = count.fetch_add(1, Ordering::SeqCst);
                        debug!("[#{id}] Incoming connection: <{remote_addr}>");

                        let context = context.clone();
                        let proxy =
                            service_fn(move |req| App::handle_connection(context.clone(), id, req));

                        tokio::spawn(async move {
                            if let Err(e) = http1::Builder::new()
                                    .keep_alive(true)
                                    .preserve_header_case(true)
                                    .serve_connection(stream, proxy)
                                    .with_upgrades()
                                    .await {
                                error!("Server error: {e}");
                            }
                        });
                    }
                    _ = (&mut rx) => { break; }
                }
            }
        });

        signal::ctrl_c().await?;
        let _ = tx.send(());
        Ok(())
    }

    pub async fn run(self) -> Result<(), String> {
        // Separate to avoid add more logic
        if matches!(self.context.mode, OperationMode::Transparent) {
            todo!("Wait a little more :(");
        }

        App::serve_http(self.context)
            .await
            .map_err(|e| format!("Server Error: {}", e))?;

        info!("Exiting application...");
        Ok(())
    }
}
