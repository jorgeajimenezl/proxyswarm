extern crate clap;
use std::net::SocketAddr;

use clap::{
    crate_authors, crate_description, crate_name, crate_version, Arg, ArgAction, Command, ValueHint,
};

pub mod acl;
pub mod app;
pub mod core;
pub mod error;
pub mod http;
pub mod proxy;
pub mod transport;
pub mod utils;

use crate::app::App;
use log::{error, info, LevelFilter};
use log4rs::{
    append::console::{ConsoleAppender, Target},
    config::{Appender, Config, Root},
    encode::pattern::PatternEncoder,
    filter::threshold::ThresholdFilter,
};

#[cfg(target_family = "unix")]
static DEFAULT_CONFIGURATION_FILE_PATH: &str = "/etc/proxyswarm.conf";
#[cfg(target_family = "windows")]
static DEFAULT_CONFIGURATION_FILE_PATH: &str = "./proxyswarm.conf";

fn main() {
    let matches = Command::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!("\n"))
        .about(crate_description!())
        .arg(
            Arg::new("verbose")
                .long("verbose")
                .short('v')
                .action(ArgAction::Count)
                .help("Sets the level of verbosity"),
        )
        .arg(
            Arg::new("quiet")
                .long("quiet")
                .short('q')
                .conflicts_with("verbose")
                .action(ArgAction::SetTrue)
                .help("Enable quiet mode"),
        )
        .arg(
            Arg::new("proxy")
                .long("proxy")
                .short('p')
                .action(ArgAction::Set)
                .value_name("[proto://][username[:password]@]host:port")
                .help("Uri of the proxy"),
        )
        .arg(
            Arg::new("mode")
                .long("mode")
                .short('m')
                .action(ArgAction::Set)
                .value_parser(["http", "socks", "transparent"])
                .ignore_case(true)
                .default_value("http")
                .help("Work mode"),
        )
        .arg(
            Arg::new("bind-address")
                .long("bind-address")
                .short('b')
                .action(ArgAction::Set)
                .value_parser(str::parse::<SocketAddr>)
                .value_name("ip:port")
                .help("Address to listen connections"),
        )
        .arg(
            Arg::new("bypass")
                .long("bypass")
                .short('a')
                .action(ArgAction::Append)
                .help("Avoid proxify the request with these destinations"),
        )
        .arg(
            Arg::new("deny")
                .long("deny")
                .short('d')
                .action(ArgAction::Append)
                .help("Deny the requests with this destination"),
        )
        .arg(
            Arg::new("file")
                .long("file")
                .short('f')
                .action(ArgAction::Set)
                .default_value(DEFAULT_CONFIGURATION_FILE_PATH)
                .value_hint(ValueHint::FilePath)
                .help("Path to configuration file"),
        )
        .get_matches();

    let level = match matches.get_count("verbose") {
        _ if matches.get_flag("quiet") => LevelFilter::Off,
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        _ => LevelFilter::Trace,
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
        error!("Error initializing logger: {e}");
        std::process::exit(1);
    }

    info!("Application started");

    // Load configuration file
    let config = {
        let path = matches.get_one::<String>("file").unwrap();

        match config::Config::builder()
            .add_source(config::Environment::with_prefix(crate_name!()))
            .add_source(config::File::new(path, config::FileFormat::Ini))
            .set_override_option("proxy.uri", matches.get_one::<String>("proxy").cloned())
            .unwrap()
            .set_override_option("general.mode", matches.get_one::<String>("mode").cloned())
            .unwrap()
            .set_override_option::<_, String>(
                "general.bind-address",
                matches
                    .get_one::<SocketAddr>("bind-address")
                    .cloned()
                    .map(|v| v.to_string()),
            )
            .unwrap()
            .set_override_option(
                "general.bypass",
                matches
                    .get_many::<String>("bypass")
                    .map(|v| v.cloned().collect::<Vec<_>>()),
            )
            .unwrap()
            .set_override_option(
                "general.deny",
                matches
                    .get_many::<String>("deny")
                    .map(|v| v.cloned().collect::<Vec<_>>()),
            )
            .unwrap()
            .build()
        {
            Ok(v) => {
                info!("Successful loaded configuration file from {path}");
                v
            }
            Err(e) => {
                error!("Error loading configuration file: {e}");
                std::process::exit(1);
            }
        }
    };

    // Main Logic
    let app = match App::from_config(config) {
        Ok(v) => v,
        Err(e) => {
            error!("{e}");
            std::process::exit(1);
        }
    };

    do_work(app);
}

#[tokio::main]
async fn do_work(app: App) {
    if let Err(e) = app.run().await {
        error!("{e}");
    }
}
