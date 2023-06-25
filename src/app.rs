use super::http::{empty, ProxyHttp};
use super::proxy::{Credentials, Proxy};
use crate::error::Error;

use tokio::net::TcpListener;
use tokio::{self, signal, sync::oneshot};

use http_body_util::combinators::BoxBody;
use hyper::{
    body::{Bytes, Incoming},
    header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::http1,
    service::service_fn,
    Request, Response, StatusCode,
};

use config::Config;
use log::{debug, error, info, trace};

use std::sync::Mutex;
use std::{
    convert::Infallible,
    net::SocketAddr,
    str::FromStr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};

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
    pub bypass: Vec<String>,
    pub mode: OperationMode,

    digest_state: Arc<Mutex<crate::http::DigestState>>,
}

pub struct App {
    context: AppContext,
}

impl App {
    fn build_appcontext(config: Config) -> Result<AppContext, Error> {
        let mut proxies = Vec::new();
        let mut bypass = Vec::new();

        for value in config
            .get_array("general.bypass")
            .unwrap_or(vec!["127.0.0.1".into()])
        {
            bypass.push(value.into_string()?);
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
            bypass,
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
        debug!("[#{}] Requested: {}", id, req.uri());
        trace!("[#{}] Request struct: {:?}", id, req);

        // Remove proxy headers
        if matches!(context.mode, OperationMode::Proxy) {
            let headers = req.headers_mut();
            headers.remove(PROXY_AUTHENTICATE);
            headers.remove(PROXY_AUTHORIZATION);
        }

        // Forward the request
        let client = ProxyHttp::new(
            id,
            context.proxies,
            context.bypass,
            Arc::clone(&context.digest_state),
        );
        let res = match client.request(req).await {
            Ok(v) => v,
            Err(e) => {
                error!("Error forwarding request to destination: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .body(empty())
                    .unwrap());
            }
        };

        debug!("[#{}] Connection processed successful", id);
        Ok(res)
    }

    async fn serve_http(context: AppContext) -> Result<(), Error> {
        let addr = context.addr;
        let count = Arc::new(AtomicU32::new(0));

        let tcp_listener = TcpListener::bind(addr).await?;
        info!(
            "Proxy listening at http://{}. Press Ctrl+C to stop it",
            addr
        );

        let (tx, mut rx) = oneshot::channel();

        // Main loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    conn = tcp_listener.accept() => {
                        let (stream, remote_addr) = match conn {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Unable to accept incomming TCP connection: {}", e);
                                return;
                            }
                        };

                        // Get connections count
                        let id = count.fetch_add(1, Ordering::SeqCst);
                        debug!("[#{}] Incoming connection: <{}>", id, remote_addr);

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
                                error!("Server error: {}", e);
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
