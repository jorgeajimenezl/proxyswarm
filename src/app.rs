use super::http::DigestState;
use super::proxy::{Credentials, Proxy};
use crate::acl::{Acl, Rule};
use crate::error::Error;
use crate::transport::Server;
use crate::transport::{http::HttpServer, socks::SocksServer};

use config::Config;
use log::info;

use std::{
    net::SocketAddr,
    str::FromStr,
    sync::{Arc, Mutex},
};

#[derive(Clone, Debug, strum::Display, strum::EnumString)]
#[strum(serialize_all = "lowercase")]
pub enum TransportMode {
    Transparent,
    Http,
    Socks,
}

#[derive(Clone)]
pub struct AppContext {
    pub addr: SocketAddr,
    pub proxies: Vec<Proxy>,
    pub mode: TransportMode,
    pub acl: Acl,

    pub digest_state: Arc<Mutex<DigestState>>,
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
            acl.add(&value.to_string(), Rule::Bypass)?;
        }

        if let Ok(deny_values) = config.get_array("general.deny") {
            for value in deny_values {
                acl.add(&value.to_string(), Rule::Deny)?;
            }
        }

        let mode = config
            .get_string("general.mode")
            .unwrap_or(String::from("http"))
            .parse::<TransportMode>().map_err(|_| "Proxy mode not available")?;

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

    pub async fn run(self) -> Result<(), String> {
        let server = match self.context.mode {
            TransportMode::Http => HttpServer::serve(self.context),
            TransportMode::Socks => SocksServer::serve(self.context),
            TransportMode::Transparent => {
                unimplemented!("Wait a little more :(");
            }
        };

        // wait for server
        server
            .await
            .map_err(|e| format!("Server Error: {}", e))?;

        info!("Exiting application...");
        Ok(())
    }
}
