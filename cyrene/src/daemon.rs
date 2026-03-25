use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tungstenite::{client, ClientRequestBuilder};
use tungstenite::Error as WsError;
use tungstenite::protocol::{frame, CloseFrame, Message};
use ureq::{self, http::Uri};

use crate::config;

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

#[derive(Debug, Serialize)]
struct TestMessage<'a> {
    id: u64,
    kind: &'a str,
    body: &'a str,
}

#[derive(Debug, Deserialize, Serialize)]
enum SocketMessage {
    Authenticate { name: String },

    JobRecvStarted { id: i32, listen_addr: String },
    JobRecvTerminated { id: i32, code: i32, reason: String },
}

#[derive(Error, Debug)]
pub enum RunError {
    #[error("config error: {0}")]
    Config(String),

    #[error("json parse error: {0}")]
    JsonEncoding(#[from] serde_json::Error),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("ws api error: {0}")]
    WebSocket(#[from] tungstenite::Error),

    #[error("{0}")]
    Misc(String),
}

type Result<T> = ::std::result::Result<T, RunError>;

pub fn run_call_master() -> Result<String> {
    // read initial configuration
    let cfg = config::read_cached_file()?;
    let url = format!("{}/test", cfg.uri_http());
    println!("sending test message to master: {}", url);

    // generate the json message
    let test_message = TestMessage { id: 0, kind: "test", body: "hello, world." };

    let json_blob = serde_json::to_vec(&test_message)
        .map_err(|e| RunError::Misc(format!("error: {e:?}")))?;

    // load our crypto primitives
    let key_material = BASE64.decode(cfg.controller.privkey.as_bytes())
        .expect("failed to decode key from stdin");
    
    let sk_bytes: &[u8; 32] = key_material.as_slice().try_into()
        .expect(&format!("expected [32] bytes, got [{}]", key_material.len()));

    let sk = SigningKey::from_bytes(sk_bytes);

    // issue signed request
    let digest = Sha256::digest(&json_blob);
    println!("sending digest ({}): {digest:x}", json_blob.len());

    let sig = sk.sign(&digest);
    let enc = BASE64.encode(&sig.to_bytes());
    println!("sending signature: {enc}");

    let mut resp = ureq::post(url)
        .header("content-type", "application/json")
        .header("x-cyrene-id", "hitomi") // TODO: hardcoded host ID
        .header("x-cyrene-sig", enc)
        .send(&json_blob)
        .map_err(|e| RunError::Misc(format!("req error: {e:?}")))?;

    let resp_body = resp.body_mut().read_to_string()
        .map_err(|e| RunError::Misc(format!("error: {e:?}")))?;

    Ok(resp_body)
}

pub fn run_command_queue() -> Result<String> {
    println!("booting web socket ...");
    let cfg = config::read_cached_file()?;

    let uri = cfg.uri_ws().parse::<Uri>()
       .map_err(|e| RunError::Misc(format!("invalid uri: {e:?}")))?;

    // ugh; we have to do this ourselves so we can set the socket non-blocking
    let host = uri.host().expect("no host?"); // TODO: tls
    let port = uri.port_u16().expect("no port?"); // TODO: default 80/443

    let addr = format!("{host}:{port}")
        .to_socket_addrs()?
        .find(|a| a.is_ipv4())
        .expect("no socket addr");

    eprintln!("tcp connect: {addr:?} for {uri:?}");

    // create non-blocking stream
    let stream = TcpStream::connect(addr)?;

    let ws_config = ClientRequestBuilder::new(uri)
        .with_header("x-cyrene-id", "hitomi") // TODO: hardcoded host ID
        .with_sub_protocol("x-cyrene-v1");

    let (mut socket, _resp) = client::client(ws_config, stream.try_clone()?)
        .map_err(|err| RunError::Misc(format!("handshake error: {err:?}")))?;

    socket.flush()?;
    stream.set_nonblocking(true)?;
    println!("connected ws client for: {}", cfg.uri_ws());

    'ws: loop {
        std::thread::sleep(Duration::from_millis(100));

        if !socket.can_read() { continue 'ws } // non-blocking

        let ws_msg_frame = match socket.read() {
            Ok(frame) => frame,
            Err(WsError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => { continue 'ws },
            Err(err) => return Err(RunError::from(err)),
        };

        let message = match ws_msg_frame {
            Message::Text(utf8_bytes) => utf8_bytes.to_string(),

            Message::Close(Some(frame)) => match reason_for_close(frame) {
                (normal, reason) => {
                    eprintln!("socket closed [n? {normal}]: {reason}");
                    break 'ws;
                },
            },

            Message::Close(None) => {
                eprintln!("socket closed abnormally w/o reason");
                break 'ws;
            },

            Message::Ping(_) => { continue 'ws; },

            _ => {
                println!("wtf");
                continue 'ws;
            },
        };

        println!("got: {message}");

        if false { break 'ws }
    }

    Ok("command wait queue exited ...".into())
}

fn reason_for_close(reason: frame::CloseFrame) -> (bool, String) {
    use frame::coding::CloseCode;
    match reason {
        CloseFrame { code: CloseCode::Normal, reason } => {
            (true, reason.to_string())
        },

        CloseFrame { reason, .. } => (false, reason.to_string()),
    }
}

#[allow(dead_code)] // TODO: dev sandbox ...
pub fn run_websocket_test() -> Result<String> {
    let uri = "ws://localhost:4000/api/websocket".parse()
        .map_err(|e| RunError::Misc(format!("invalid uri: {e:?}")))?;

    let ws_config = ClientRequestBuilder::new(uri)
        .with_header("x-cyrene-id", "hitomi") // TODO: hardcoded host ID
        .with_sub_protocol("x-cyrene-v1");

    let (mut socket, _response) = client::connect(ws_config)?;
    println!("connected ...");

    let msg_bytes = frame::Utf8Bytes::from_static("woah broah, woah ...");
    socket.write(Message::Text(msg_bytes))?;
    socket.flush()?;
    println!("wrote message");

    // test
    let foo = SocketMessage::Authenticate { name: "hitomi".to_string() };
    let json_bytes = serde_json::to_string(&foo)?;
    println!("message: {json_bytes}");

    'ws: loop {
        std::thread::sleep(Duration::from_millis(100));
        if !socket.can_read() { continue; }

        let message = match socket.read()? {
            Message::Text(utf8_bytes) => utf8_bytes.to_string(),
            _ => panic!("unhandled message type ..."),
        };

        println!("got: {message}");
        break 'ws // exit after our echo
    }

    Err(RunError::Misc(format!("not yet implemented")))
}
