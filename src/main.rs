extern crate clap;
use clap::{App, Arg};

use tokio;

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

use tokio::{signal, sync::Mutex};

use hyper::{
	header::{PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
	server::conn::AddrStream,
	service::{make_service_fn, service_fn},
	Body, HeaderMap, Request, Response, Server, StatusCode, Uri,
};

use configparser::ini::Ini;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;

use log::{debug, error, info, trace, LevelFilter};
use log4rs::{
	append::console::{ConsoleAppender, Target},
	config::{Appender, Config, Root},
	encode::pattern::PatternEncoder,
	filter::threshold::ThresholdFilter,
};

#[derive(Clone, Debug)]
struct AppContext {
	pub addr: SocketAddr,
	pub proxies: Vec<Proxy>,
	pub bypass: Vec<String>,
}

macro_rules! try_or_error {
	($x:expr, $s:literal, $error:expr) => {
		match $x {
			Ok(v) => v,
			Err(e) => {
				error!($s, e);
				return Ok($error);
			}
		}
	};
}

fn main() {
	let matches = App::new("proxyswarm")
						.version("0.1.2")
						.author("Jorge A. Jiménez Luna <jorgeajimenezl17@gmail.com>")
						.about("Proxyswarm is a lightweight proxy that allows redirect HTTP(S) traffic through a proxy.")
						.arg(Arg::with_name("verbosity")
						  	.long("verbosity")
							.short("v")
							.multiple(true)
							.help("Sets the level of verbosity"))
                        .arg(Arg::with_name("file")
							.long("file")
							.short("f")
							.default_value("/etc/proxyswarm.conf")
							.takes_value(true)
							.help("Path to configuration file."))
						.arg(Arg::with_name("test-file")
							.long("test-file")
							.short("t")
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
		info!("Conguration file analized");
		std::process::exit(1);
	}

	do_work(context);
}

fn build_appcontext(config: &Ini) -> Result<AppContext, String> {
	// Create empty context
	let mut proxies = Vec::new();
	let mut bypass = Vec::new();

	if let Some(v) = config.get("general", "bypass") {
		bypass.extend(v.split(",").map(|x| String::from(x)));
	}

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
	req.headers_mut().remove(PROXY_AUTHENTICATE);
	req.headers_mut().remove(PROXY_AUTHORIZATION);

	let error = Response::builder()
		.status(StatusCode::INTERNAL_SERVER_ERROR)
		.body(Body::empty())
		.unwrap();

	let client = ProxyClient::from_parts(context.proxies, context.bypass);

	// Forward the request
	let res = try_or_error!(
		client.request(id, req).await,
		"Error forwarding request to destination: {}",
		error
	);

	debug!("[#{}] Connection processed successful", id);
	return Ok(res);
}

#[tokio::main]
async fn do_work(context: AppContext) {
	let addr = context.addr.clone();
	let count = Arc::new(Mutex::new(0));

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
	}
	info!("Exiting application...");
}
