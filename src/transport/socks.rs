use super::Server;

use crate::{
    acl::Rule,
    app::AppContext,
    core::{MaybeNamedHost, MaybeNamedSock, ProxyRequest},
    error::Error,
    http::HttpHandler,
};

use socks5_impl::{
    protocol::{Address, Reply},
    server::{auth::NoAuth, ClientConnection, IncomingConnection, Server as Socks5Server},
};
use std::{net::SocketAddr, sync::Arc};
use tokio::net::TcpStream;

use async_trait::async_trait;
use log::{debug, error, info, trace};

pub struct SocksServer {
    server: Socks5Server<()>,
}

impl SocksServer {
    pub async fn handle_socks_connection(
        context: AppContext,
        id: u32,
        conn: IncomingConnection<()>,
    ) -> socks5_impl::Result<()> {
        let (conn, _res) = conn.authenticate().await?;
        let (connect, addr) = match conn.wait_request().await? {
            ClientConnection::Bind(bind, _) => {
                let mut conn = bind
                    .reply(Reply::CommandNotSupported, Address::unspecified())
                    .await?;
                return Ok(conn.shutdown().await?);
            }
            ClientConnection::UdpAssociate(udp, _) => {
                let mut conn = udp
                    .reply(Reply::CommandNotSupported, Address::unspecified())
                    .await?;
                return Ok(conn.shutdown().await?);
            }
            ClientConnection::Connect(connect, addr) => (connect, addr),
        };

        debug!("[#{id}] Requested: {}", addr);

        let rule = match &addr {
            Address::DomainAddress(domain, _) => context.acl.match_hostname(domain),
            Address::SocketAddress(sock) => context.acl.match_addr(sock.ip()),
        };

        match rule {
            Rule::Bypass => {
                info!("[#{id}] Bypassing connection to {addr}");

                let target = match addr {
                    Address::DomainAddress(domain, port) => {
                        TcpStream::connect((domain, port)).await
                    }
                    Address::SocketAddress(addr) => TcpStream::connect(addr).await,
                };

                if let Ok(mut target) = target {
                    let mut conn = connect
                        .reply(Reply::Succeeded, Address::unspecified())
                        .await?;
                    trace!("[#{id}] {} -> {}", conn.peer_addr()?, target.peer_addr()?);
                    tokio::io::copy_bidirectional(&mut target, &mut conn).await?;
                } else {
                    let mut conn = connect
                        .reply(Reply::HostUnreachable, Address::unspecified())
                        .await?;
                    conn.shutdown().await?;
                }

                return Ok(());
            }
            Rule::Deny => {
                info!("[#{id}] Deny connection to {addr}");
                let mut conn = connect
                    .reply(Reply::ConnectionNotAllowed, Address::unspecified())
                    .await?;
                return Ok(conn.shutdown().await?);
            }
            _ => {}
        }

        // Forward the request
        let client = HttpHandler::new(id, context.proxies, Arc::clone(&context.digest_state));
        let conn = connect
            .reply(Reply::Succeeded, Address::unspecified())
            .await?;

        let request = ProxyRequest {
            destination: MaybeNamedSock {
                host: match &addr {
                    Address::DomainAddress(domain, _) => MaybeNamedHost::Hostname(domain.clone()),
                    Address::SocketAddress(sock) => MaybeNamedHost::Address(sock.ip()),
                },
                port: addr.port(),
            },
            inner: TcpStream::from(conn),
            _phanton: std::marker::PhantomData,
        };

        if let Err(e) = client.request(request).await {
            error!("Error forwarding request to destination: {e}");
        }

        debug!("[#{id}] Connection processed successful");
        Ok(())
    }
}

#[async_trait]
impl Server for SocksServer {
    type StreamType = IncomingConnection<()>;

    async fn bind(addr: SocketAddr) -> std::io::Result<Box<Self>> {
        let server = Socks5Server::bind(addr, Arc::new(NoAuth)).await?;
        Ok(Box::new(SocksServer { server }))
    }

    async fn accept(&self) -> std::io::Result<(Self::StreamType, SocketAddr)> {
        self.server.accept().await
    }

    async fn handle_connection(
        context: AppContext,
        id: u32,
        stream: Self::StreamType,
    ) -> Result<(), Error> {
        Ok(Self::handle_socks_connection(context, id, stream).await?)
    }
}
