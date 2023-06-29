use crate::{app::AppContext, error::Error};
use async_trait::async_trait;

pub mod http;
// pub mod tcp;

#[async_trait]
pub trait Server {
    async fn serve(context: AppContext) -> Result<(), Error>;
}
