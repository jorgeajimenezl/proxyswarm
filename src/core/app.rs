use super::http::{empty, ProxyHttp};
use super::proxy::{Credentials, Proxy};

use tokio::net::TcpListener;
use tokio::{self, signal, sync::oneshot};

use http_body_util::combinators::BoxBody;
use hyper::{
    body::{Bytes, Incoming},
    header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::http1,
    service::service_fn,
    HeaderMap, Request, Response, StatusCode, Uri,
};

use configparser::ini::Ini;
use log::{debug, error, info, trace};
use std::io::Error;

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
}

pub struct App {
    context: AppContext,
}

impl App {
    fn build_appcontext(config: &Ini) -> Result<AppContext, String> {
        let mut proxies = Vec::new();
        let bypass = config
            .get("general", "bypass")
            .unwrap_or(String::from("127.0.0.1"))
            .split(",")
            .map(|x| String::from(x))
            .collect();

        let mode = config
            .get("general", "mode")
            .unwrap_or(String::from("proxy"))
            .parse::<OperationMode>()?;

        // Get the proxies
        let mut sessions = Vec::new();
        for (k, _) in config.get_map_ref() {
            if k.to_lowercase().ends_with("proxy") {
                sessions.push(k);
            }
        }
        for k in sessions {
            let username = config.get(k, "username");
            let password = config.get(k, "password");
            let uri = config
                .get(k, "uri")
                .ok_or("Missing uri field in proxy session")?;

            if (username != None && password == None) || (username == None && password != None) {
                return Err(String::from(
                    "The proxy session must include username and password or neither",
                ));
            }

            let proxy = Proxy {
                uri: Uri::from_str(&uri).map_err(|e| format!("Error parsing proxy uri: {}", e))?,
                headers: HeaderMap::new(),
                credentials: if username == None {
                    None
                } else {
                    Some(Credentials {
                        username: username.unwrap(),
                        password: password.unwrap(),
                    })
                },
            };

            proxies.push(proxy);
        }

        let listen_addr = SocketAddr::new(
            config
                .get("general", "bind-address")
                .unwrap_or(String::from("0.0.0.0"))
                .parse()
                .map_err(|e| format!("Error parsing address interface to bind the app: {}", e))?,
            config
                .get("general", "bind-port")
                .unwrap_or(String::from("3128"))
                .parse::<u16>()
                .map_err(|e| format!("Error parsing port to bind the app: {}", e))?,
        );

        Ok(AppContext {
            addr: listen_addr,
            mode,
            proxies,
            bypass,
        })
    }

    pub fn from_config(config: &Ini) -> Result<Self, String> {
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
        let client = ProxyHttp::new(id, context.proxies, context.bypass);
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
        return Ok(res);
    }

    async fn serve_http(context: AppContext) -> Result<(), Error> {
        let addr = context.addr.clone();
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
            todo!();
        }

        App::serve_http(self.context)
            .await
            .map_err(|e| format!("Server Error: {}", e))?;

        info!("Exiting application...");
        Ok(())
    }
}
