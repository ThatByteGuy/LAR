use thiserror::Error;

pub type Result<T> = std::result::Result<T, LarError>;

#[derive(Debug, Error)]
pub enum LarError {
    #[error("fetch failed for {0}: {1}")]
    Fetch(String, String),
    // fail-closed: caller must treat this as REVIEW
    #[error("parse unreliable: {0}")]
    Parse(String),
    #[error("rule database invalid: {0}")]
    Rules(String),
    #[error("config invalid: {0}")]
    Config(String),
    #[error("io: {0}")]
    Io(String),
    #[error("verification failed: {0}")]
    Verify(String),
    #[error("refused: {0}")]
    Refused(String),
}

impl From<std::io::Error> for LarError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e.to_string())
    }
}
