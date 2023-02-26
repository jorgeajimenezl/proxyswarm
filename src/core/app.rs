use super::client::ProxyClient;
use super::proxy::{Credentials, Proxy};

use tokio::{
    self,
    net::TcpListener,
    signal,
    sync::{oneshot, Mutex},
};
use tokio_native_tls::{
    native_tls::{self, Identity},
    TlsAcceptor,
};

use hyper::{
    header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::{AddrStream, Http},
    service::{make_service_fn, service_fn},
    Body, HeaderMap, Request, Response, Server, StatusCode, Uri,
};

use configparser::ini::Ini;
use log::{debug, error, info, trace};
use std::{convert::Infallible, fs, net::SocketAddr, str::FromStr, sync::Arc};

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

macro_rules! try_or_error {
    ($x:expr, $s:literal) => {
        match $x {
            Ok(v) => v,
            Err(e) => {
                error!($s, e);
                return;
            }
        }
    };
}

#[derive(Clone)]
pub struct AppContext {
    pub addr: SocketAddr,
    pub proxies: Vec<Proxy>,
    pub bypass: Vec<String>,
    pub mode: OperationMode,
    pub tls: Option<TlsAcceptor>,
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

        let tls_identity = if config
            .sections()
            .iter()
            .map(|s| s.to_lowercase())
            .any(|e| e == "tls")
        {
            let cert_path = config.get("tls", "cert_path").ok_or(String::from(
                "If tls is active then you must set the certificate path",
            ))?;
            let cert_pass = config.get("tls", "password").ok_or(String::from(
                "If tls is active then you must set the certificate password",
            ))?;
            let identity =
                fs::read(cert_path).map_err(|e| format!("Error reading the certificate: {}", e))?;
            let identity = Identity::from_pkcs12(&identity, &cert_pass)
                .map_err(|e| format!("Error parsing certificate: {}", e))?;

            let tls = TlsAcceptor::from(
                native_tls::TlsAcceptor::new(identity)
                    .map_err(|e| format!("Unable create TLS context: {}", e))?,
            );
            Some(tls)
        } else {
            None
        };

        Ok(AppContext {
            tls: tls_identity,
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
        addr: SocketAddr,
        count: Arc<Mutex<u32>>,
        mut req: Request<Body>,
    ) -> Result<Response<Body>, Infallible> {
        // Get connections count
        let mut c = count.lock().await;
        let id = *c;
        *c += 1;
        drop(c);
        drop(count);

        debug!("[#{}] Incoming connection: {}", id, addr);
        debug!("[#{}] Requested: {}", id, req.uri());
        trace!("[#{}] Request struct: {:?}", id, req);

        // Remove proxy headers
        let headers = req.headers_mut();
        headers.remove(PROXY_AUTHENTICATE);
        headers.remove(PROXY_AUTHORIZATION);

        // Forward the request
        let client = ProxyClient::from_parts(context.proxies, context.bypass);
        let res = match client.request(id, req).await {
            Ok(v) => v,
            Err(e) => {
                error!("Error forwarding request to destination: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap());
            }
        };

        debug!("[#{}] Connection processed successful", id);
        return Ok(res);
    }

    async fn serve_https(context: AppContext) -> Result<(), std::io::Error> {
        let count = Arc::new(Mutex::new(0));
        let listener = TcpListener::bind(context.addr).await?;

        info!(
            "Proxy listening at https://{}. Press Ctrl+C to stop it",
            context.addr
        );

        let (tx, mut rx) = oneshot::channel::<()>();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    k = listener.accept() => {
                        let acceptor = context.tls.clone();
                        let context = context.clone();
                        let count = count.clone();

                        let (stream, addr) = try_or_error!(k, "Unable to accept incomming TCP connection: {}");
                        let service =
                            service_fn(move |req| App::handle_connection(context.clone(), addr, count.clone(), req));
                        tokio::task::spawn(async move {
                            let tls_stream = try_or_error!(acceptor.unwrap().accept(stream).await, "TLS handshake error: {}");
                            if let Err(e) = Http::new()
                                    .http1_only(true)
                                    .http1_keep_alive(true)
                                    .serve_connection(tls_stream, service)
                                    .await {
                                error!("Server Error: {}", e);
                            }
                        });
                    }
                    _ = (&mut rx) => {
                        break;
                    }
                };
            }
        });

        signal::ctrl_c().await?;
        let _ = tx.send(());
        Ok(())
    }

    pub async fn run(self) -> Result<(), String> {
        // Separate to avoid add more logic
        if matches!(self.context.tls, None) {
            let addr = self.context.addr.clone();
            let count = Arc::new(Mutex::new(0));

            let make_service = make_service_fn(move |conn: &AddrStream| {
                let count = count.clone();
                let context = self.context.clone();
                let addr = conn.remote_addr();

                let service = service_fn(move |req| {
                    App::handle_connection(context.clone(), addr, count.clone(), req)
                });

                async move { Ok::<_, Infallible>(service) }
            });

            let server = Server::bind(&addr).serve(make_service);
            info!(
                "Proxy listening at http://{}. Press Ctrl+C to stop it",
                addr
            );

            // Prepare some signal for when the server should start shutting down...
            let graceful = server.with_graceful_shutdown(async {
                signal::ctrl_c()
                    .await
                    .expect("Failed to install CTRL+C signal handler");
            });

            graceful.await.map_err(|e| format!("Server Error: {}", e))?;
        } else {
            App::serve_https(self.context)
                .await
                .map_err(|e| format!("Server Error: {}", e))?;
        }
        info!("Exiting application...");
        Ok(())
    }
}
