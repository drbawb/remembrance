use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize)]
pub struct TestMessage<'a> {
    pub id: u64,
    pub kind: &'a str,
    pub body: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum SocketMessage {
    Authenticate { name: String },

    JobRecvStarted { id: i32, listen_addr: String },
    JobRecvTerminated { id: i32, code: i32, reason: String },
}
