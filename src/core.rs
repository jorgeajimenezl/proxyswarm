use async_trait::async_trait;
use hyper::{body::Incoming, Request};
use std::{
    marker::PhantomData,
    net::{IpAddr, SocketAddr},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

use crate::error::Error;

#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub(crate) enum MaybeNamedHost {
    Address(IpAddr),
    Hostname(String),
}

impl From<IpAddr> for MaybeNamedHost {
    fn from(value: IpAddr) -> Self {
        MaybeNamedHost::Address(value)
    }
}

impl From<&str> for MaybeNamedHost {
    fn from(value: &str) -> Self {
        MaybeNamedHost::Hostname(value.to_string())
    }
}

impl std::fmt::Display for MaybeNamedHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MaybeNamedHost::Address(addr) => addr.fmt(f),
            MaybeNamedHost::Hostname(name) => name.fmt(f),
        }
    }
}

#[derive(Hash, Clone, Eq, PartialEq, Debug)]
pub struct MaybeNamedSock {
    pub(crate) host: MaybeNamedHost,
    pub(crate) port: u16,
}

impl TryFrom<MaybeNamedSock> for SocketAddr {
    type Error = Error;
    fn try_from(value: MaybeNamedSock) -> Result<Self, Self::Error> {
        let ip = match value.host {
            MaybeNamedHost::Address(addr) => addr,
            MaybeNamedHost::Hostname(e) => {
                return Err(e.into());
            }
        };
        Ok(SocketAddr::new(ip, value.port))
    }
}

impl From<SocketAddr> for MaybeNamedSock {
    fn from(addr: SocketAddr) -> Self {
        Self {
            host: MaybeNamedHost::Address(addr.ip()),
            port: addr.port(),
        }
    }
}

impl std::fmt::Display for MaybeNamedSock {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let MaybeNamedHost::Address(IpAddr::V6(addr)) = self.host {
            write!(f, "[{}]:{}", addr, self.port)
        } else {
            write!(f, "{}:{}", self.host, self.port)
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
    pub destination: MaybeNamedSock,
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
