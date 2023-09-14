use super::Server;
use crate::{app::AppContext, core::ProxyRequest, error::Error, http::HttpHandler};

use async_trait::async_trait;
use std::sync::Arc;
use log::{debug, error};
use tokio::net::TcpStream;

pub struct TcpServer;

impl TcpServer {
    async fn handle_tcp_connection(context: AppContext, id: u32, mut stream: TcpStream) {
        let peer_addr = match stream.peer_addr() {
            Ok(x) => x,
            Err(e) => {
                error!("[#{id}] Unable to get destination address: {e}");
                return;
            }
        };

        let client = HttpHandler::new(id, context.proxies, Arc::clone(&context.digest_state));

        let request = ProxyRequest {
            destination: peer_addr.into(),
            inner: stream,
            _phanton: std::marker::PhantomData,
        };

        if let Err(e) = client.request(request).await {
            error!("Error forwarding request to destination: {e}");
            return;
        }

        debug!("[#{id}] Connection processed successful");
    }
}

#[async_trait]
impl Server for TcpServer {
    async fn serve(context: AppContext) -> Result<(), Error> {
        Ok(())
    }
}
