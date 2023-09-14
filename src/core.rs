use async_trait::async_trait;
use hyper::{body::Incoming, Request};
use std::{
    marker::PhantomData,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::error::Error;

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Address {
    SocketAddress(SocketAddr),
    DomainAddress(String, u16),
}

impl Address {
    pub fn port(&self) -> u16 {
        match self {
            Self::SocketAddress(addr) => addr.port(),
            Self::DomainAddress(_, port) => *port,
        }
    }

    pub fn domain(&self) -> String {
        match self {
            Self::SocketAddress(addr) => addr.ip().to_string(),
            Self::DomainAddress(addr, _) => addr.clone(),
        }
    }
}

impl TryFrom<Address> for SocketAddr {
    type Error = std::io::Error;

    fn try_from(address: Address) -> std::result::Result<Self, Self::Error> {
        match address {
            Address::SocketAddress(addr) => Ok(addr),
            Address::DomainAddress(addr, port) => {
                if let Ok(addr) = addr.parse::<Ipv4Addr>() {
                    Ok(SocketAddr::from((addr, port)))
                } else if let Ok(addr) = addr.parse::<Ipv6Addr>() {
                    Ok(SocketAddr::from((addr, port)))
                } else {
                    let err = format!("domain address {addr} is not supported");
                    Err(Self::Error::new(std::io::ErrorKind::Unsupported, err))
                }
            }
        }
    }
}

impl From<&SocketAddr> for Address {
    fn from(addr: &SocketAddr) -> Self {
        Address::SocketAddress(*addr)
    }
}

impl std::fmt::Display for Address {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Address::DomainAddress(hostname, port) => write!(f, "{hostname}:{port}"),
            Address::SocketAddress(socket_addr) => write!(f, "{socket_addr}"),
        }
    }
}

#[async_trait]
pub trait ToStream<S: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    async fn into_stream(self) -> Result<S, Error>;
}

pub struct ProxyRequest<T, S>
where
    T: ToStream<S>,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    pub destination: Address,
    pub inner: T,
    pub _phanton: PhantomData<S>,
}

impl<T, S> ProxyRequest<T, S>
where
    T: ToStream<S>,
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    pub async fn into_stream(self) -> Result<S, Error> {
        self.inner.into_stream().await
    }
}

#[async_trait]
impl ToStream<hyper::upgrade::Upgraded> for Request<Incoming> {
    async fn into_stream(self) -> Result<hyper::upgrade::Upgraded, Error> {
        Ok(hyper::upgrade::on(self).await?)
    }
}

#[async_trait]
impl ToStream<TcpStream> for TcpStream {
    async fn into_stream(self) -> Result<TcpStream, Error> {
        Ok(self)
    }
}
