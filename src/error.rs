use tokio::task::JoinError;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    DigestAuthError(#[from] digest_auth::Error),

    #[error(transparent)]
    Utf8Error(#[from] hyper::header::ToStrError),

    #[error("{0}")]
    String(String),

    #[error(transparent)]
    HyperError(#[from] hyper::Error),

    #[error(transparent)]
    HttpError(#[from] http::Error),

    #[error(transparent)]
    JoinError(#[from] JoinError),

    #[error(transparent)]
    InvalidUri(#[from] hyper::http::uri::InvalidUri),

    #[error(transparent)]
    ConfigurationFileError(#[from] config::ConfigError),

    #[error("This proxy need authentication")]
    AuthenticationRequired,
}

impl From<&str> for Error {
    fn from(err: &str) -> Self {
        Self::String(err.to_string())
    }
}

impl From<String> for Error {
    fn from(err: String) -> Self {
        Self::String(err)
    }
}
