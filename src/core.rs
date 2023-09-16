use crate::error::Error;
use hyper::{body::Incoming, Request};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};

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

    pub fn to_socket(self) -> std::io::Result<Self> {
        Ok(match self {
            Address::SocketAddress(sock) => Address::SocketAddress(sock),
            Address::DomainAddress(domain, port) => {
                Address::SocketAddress((domain, port).to_socket_addrs()?.next().unwrap())
            }
        })
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

pub struct ProxyRequest {
    pub destination: Address,
    pub(crate) inner: ProxyTransport,
}

mod sealed {
    use tokio::io::{AsyncRead, AsyncWrite};

    pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
    impl<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> AsyncStream for T {}
}

pub(crate) enum ProxyTransport {
    Request(Request<Incoming>),
    Stream(Box<(dyn sealed::AsyncStream)>),
}

impl ProxyRequest {
    pub fn from_stream<T: sealed::AsyncStream>(destination: Address, io: T) -> Self {
        Self {
            destination,
            inner: ProxyTransport::Stream(Box::new(io)),
        }
    }

    pub fn from_request(destination: Address, request: Request<Incoming>) -> Self {
        Self {
            destination,
            inner: ProxyTransport::Request(request),
        }
    }

    pub async fn into_stream(self) -> Result<Box<(dyn sealed::AsyncStream)>, Error> {
        Ok(match self.inner {
            ProxyTransport::Stream(stream) => stream,
            ProxyTransport::Request(req) => Box::new(hyper::upgrade::on(req).await?),
        })
    }

    #[inline]
    pub fn use_tunnel(&self) -> bool {
        match &self.inner {
            ProxyTransport::Request(req) => req.method() == hyper::Method::CONNECT,
            ProxyTransport::Stream(..) => true,
        }
    }
}
