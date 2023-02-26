extern crate clap;
use clap::{Arg, ArgAction, Command};

mod core {
    pub mod app;
    pub mod client;
    pub mod proxy;
    pub mod utils;
    pub mod auth {
        pub mod basic;
        pub mod digest;
    }
}

use crate::core::app::App;
use configparser::ini::Ini;
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
    let matches = Command::new("proxyswarm")
                        .version("0.1.5")
                        .author("Jorge A. Jiménez Luna <jorgeajimenezl17@gmail.com>")
                        .about("Proxyswarm is a lightweight proxy that allows redirect HTTP(S) traffic through a proxy.")
                        .arg(Arg::new("verbose")
                            .long("verbose")
                            .short('v')
                            .action(ArgAction::Count)
                            .help("Sets the level of verbosity"))
                        .arg(Arg::new("file")
                            .long("file")
                            .short('f')
                            .default_value(DEFAULT_CONFIGURATION_FILE_PATH)
                            .action(ArgAction::Set)
                            .help("Path to configuration file."))
                        .arg(Arg::new("test-file")
                            .long("test-file")
                            .short('t')
                            .action(ArgAction::SetTrue)
                            .help("Check the syntax of configuration file and exit."))
                        .get_matches();

    let level = match matches.get_count("verbose") {
        0 => LevelFilter::Info,
        1 => LevelFilter::Debug,
        2 | _ => LevelFilter::Trace,
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
    if let Err(e) = config.load(matches.get_one::<String>("file").unwrap()) {
        error!("Error loading configuration file: {}", e);
        std::process::exit(1);
    }

    // Main Logic
    let app = match App::from_config(&config) {
        Ok(v) => v,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };

    if matches.get_flag("test-file") {
        info!("Configuration file OK :)");
        std::process::exit(0);
    }

    do_work(app);
}

#[tokio::main]
async fn do_work(app: App) {
    if let Err(e) = app.run().await {
        error!("{}", e);
    }
}
