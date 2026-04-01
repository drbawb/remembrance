use crossbeam_channel as cc;
use thiserror::Error;

use std::io;

#[derive(Error, Debug)]
pub enum RunError {
    #[error("config error: {0}")]
    Config(String),
    
    #[error("io error: {0}")]
    Io(#[from] io::Error),
   
    #[error("json parse error: {0}")]
    JsonEncoding(#[from] serde_json::Error),

    #[error("ws api error: {0}")]
    WebSocket(#[from] tungstenite::Error),

    #[error("[chan] senders gone? {0}")]
    RxDisconnected(String),

    #[error("[chan] receiver hungup: {0}")]
    TxDisconnected(String),

    #[error("{0}")]
    Misc(String),
}

pub type Result<T> = ::std::result::Result<T, RunError>;
