use crate::{app::AppContext, error::Error};

use async_trait::async_trait;
use log::{debug, error, info};
use std::{
    net::SocketAddr,
    sync::{
        atomic::{AtomicU32, Ordering},
        Arc,
    },
};
use tokio::{signal, sync::oneshot};

pub mod http;
pub mod socks;
// pub mod tcp;

#[async_trait]
pub trait Server {
    type StreamType: Send;

    async fn bind(addr: SocketAddr) -> std::io::Result<Box<Self>>;
    async fn accept(&self) -> std::io::Result<(Self::StreamType, SocketAddr)>;
    async fn handle_connection(
        context: AppContext,
        id: u32,
        stream: Self::StreamType,
    ) -> Result<(), Error>;

    async fn serve(context: AppContext) -> Result<(), Error>
    where
        Self: 'static,
    {
        let addr = context.addr;
        let count = Arc::new(AtomicU32::new(0));

        let handler = Self::bind(addr).await?;
        info!("Proxy listening at [{}] {addr}. Press Ctrl+C to stop it", context.mode);

        let (tx, mut rx) = oneshot::channel();

        // Main loop
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    conn = handler.accept() => {
                        let (stream, remote_addr) = match conn {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Unable to accept incomming connection: {e}");
                                return;
                            }
                        };

                        // Get connections count
                        let id = count.fetch_add(1, Ordering::SeqCst);
                        debug!("[#{id}] Incoming connection: <{remote_addr}>");

                        let context = context.clone();
                        tokio::spawn(async move {
                            if let Err(e) = Self::handle_connection(context, id, stream).await {
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
}
