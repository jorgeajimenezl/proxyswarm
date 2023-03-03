use super::client::ProxyClient;

use std::io::Error;
use tokio::net::TcpStream;

impl ProxyClient {
    pub async fn request_transparent(&self, rid: u32, stream: TcpStream) -> Result<(), Error> {
        todo!()
    }
}