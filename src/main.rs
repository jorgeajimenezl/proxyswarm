extern crate clap;
use clap::{Command, Arg};

mod core {
	pub mod client;
	pub mod proxy;
	pub mod utils;
	pub mod auth {
		pub mod basic;
		pub mod digest;
	}
}
use crate::core::client::ProxyClient;
use crate::core::proxy::{Credentials, Proxy};

use tokio::{self, signal, sync::{Mutex, oneshot}, net::TcpListener};
use tokio_native_tls::{TlsAcceptor, native_tls::{self, Identity}};

use hyper::{
	header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
	server::conn::{AddrStream, Http},
	service::{make_service_fn, service_fn},
	Body, HeaderMap, Request, Response, Server, StatusCode, Uri,
};

use configparser::ini::Ini;
use std::{convert::Infallible, net::SocketAddr, str::FromStr, sync::Arc, fs};

use log::{debug, error, info, trace, LevelFilter};
use log4rs::{
	append::console::{ConsoleAppender, Target},
	config::{Appender, Config, Root},
	encode::pattern::PatternEncoder,
	filter::threshold::ThresholdFilter,
};

#[derive(Clone, Debug)]
enum OperationMode {
	Transparent,
	Proxy,
}

impl FromStr for OperationMode {
	type Err = String;
	fn from_str(x: &str) -> std::result::Result<Self, <Self as std::str::FromStr>::Err> {
		let x = x.to_lowercase();
		match x.as_ref() {
			"proxy" => Ok(OperationMode::Proxy),
			"transparent" => Ok(OperationMode::Transparent),
			_ => Err(String::from("Proxy mode not available")),
		}
	}
}

#[derive(Clone)]
struct AppContext {
	pub addr: SocketAddr,
	pub proxies: Vec<Proxy>,
	pub bypass: Vec<String>,
	pub mode: OperationMode,
	pub use_tls: bool,
	pub tls: Option<TlsAcceptor>
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

#[cfg(target_family = "unix")]
static DEFAULT_CONFIGURATION_FILE_PATH: &str = "/etc/proxyswarm.conf";
#[cfg(target_family = "windows")]
static DEFAULT_CONFIGURATION_FILE_PATH: &str = "./proxyswarm.conf";


fn main() {
	let matches = Command::new("proxyswarm")
						.version("0.1.4")
						.author("Jorge A. Jiménez Luna <jorgeajimenezl17@gmail.com>")
						.about("Proxyswarm is a lightweight proxy that allows redirect HTTP(S) traffic through a proxy.")
						.arg(Arg::new("verbosity")
						  	.long("verbosity")
							.short('v')
							.multiple_occurrences(true)
							.help("Sets the level of verbosity"))
                        .arg(Arg::new("file")
							.long("file")
							.short('f')
							.default_value(DEFAULT_CONFIGURATION_FILE_PATH)							
							.takes_value(true)
							.help("Path to configuration file."))
						.arg(Arg::new("test-file")
							.long("test-file")
							.short('t')
							.help("Check the syntax of configuration file and exit."))
						.get_matches();

	let level = match matches.occurrences_of("verbosity") {
		0 => LevelFilter::Error,
		1 => LevelFilter::Warn,
		2 => LevelFilter::Info,
		3 => LevelFilter::Debug,
		4 | _ => LevelFilter::Trace,
	};

	// Build a stdout logger.
	let stdout = ConsoleAppender::builder()
		.encoder(Box::new(PatternEncoder::new(
			"{d(%Y-%m-%d %H:%M:%S)} {h({l})} - {m}{n}",
		)))
		.target(Target::Stdout)
		.build();
	let log_config = Config::builder()
		.appender(
			Appender::builder()
				.filter(Box::new(ThresholdFilter::new(level)))
				.build("stdout", Box::new(stdout)),
		)
		.build(Root::builder().appender("stdout").build(LevelFilter::Trace))
		.unwrap();

	if let Err(e) = log4rs::init_config(log_config) {
		error!("Error initializing logger: {}", e);
		std::process::exit(1);
	}

	info!("Application started");

	// Load configuration file
	let mut config = Ini::new();
	if let Err(e) = config.load(matches.value_of("file").unwrap()) {
		error!("Error loading configuration file: {}", e);
		std::process::exit(1);
	}

	// Main Logic
	let context = match build_appcontext(&config) {
		Ok(v) => v,
		Err(e) => {
			error!("{}", e);
			std::process::exit(1);
		}
	};

	if matches.is_present("test-file") {
		info!("Conguration file OK :)");
		std::process::exit(0);
	}

	do_work(context);
}

fn build_appcontext(config: &Ini) -> Result<AppContext, String> {
	let mut proxies = Vec::new();
	let bypass = config.get("general", "bypass")
						.unwrap_or(String::from("127.0.0.1"))
						.split(",")
						.map(|x| String::from(x))
						.collect();

	let mode = config.get("general", "mode")
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

	let use_tls: bool;
	let tls_identity = if config.sections().iter().map(|s| s.to_lowercase()).any(|e| e == "tls") {
		let cert_path = config.get("tls", "cert_path").ok_or(String::from("If tls is active then you must set the certificate path"))?;
		let cert_pass = config.get("tls", "password").ok_or(String::from("If tls is active then you must set the certificate password"))?;
		let identity = fs::read(cert_path).map_err(|e| format!("Error reading the certificate: {}", e))?;
		let identity = Identity::from_pkcs12(&identity, &cert_pass).map_err(|e| format!("Error parsing certificate: {}", e))?;
		use_tls = true;
		
		let tls = TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).map_err(|e| format!("Unable create TLS context: {}", e))?);
		Some(tls)
	} else {
		use_tls = false;
		None
	};

	Ok(AppContext {
		use_tls: use_tls,
		tls: tls_identity,
		mode: mode,
		addr: listen_addr,
		proxies: proxies,
		bypass: bypass,
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

	let error = Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.body(Body::empty())
		.unwrap();

	let client = ProxyClient::from_parts(context.proxies, context.bypass);

	// Forward the request
	let res = match client.request(id, req).await {
		Ok(v) => v,
		Err(e) => {
			error!("Error forwarding request to destination: {}", e);
			return Ok(error)
		}
	};

	debug!("[#{}] Connection processed successful", id);
	return Ok(res);
}

async fn serve_https(count: Arc<Mutex<u32>>, context: AppContext) -> Result<(), std::io::Error> {
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
						service_fn(move |req| handle_connection(context.clone(), addr, count.clone(), req));
	
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

	signal::ctrl_c()
				.await?;
	let _ = tx.send(());
	Ok(())
}

#[tokio::main]
async fn do_work(context: AppContext) {
	let addr = context.addr.clone();
	let count = Arc::new(Mutex::new(0));
	let use_tls = context.use_tls;

	// Separate to avoid add more logic
	if !use_tls {
		let make_service = make_service_fn(move |conn: &AddrStream| {
			let count = count.clone();
			let context = context.clone();
			let addr = conn.remote_addr();
			
			let service =
				service_fn(move |req| handle_connection(context.clone(), addr, count.clone(), req));
	
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

		if let Err(e) = graceful.await {
			error!("Server Error: {}", e);
		};
	} else {
		if let Err(e) = serve_https(count, context).await {
			error!("Server Error: {}", e);
		}
	}
	info!("Exiting application...");
}
