use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;
use ureq;

use crate::config::DaemonConfig;

use std::{fs, io};

#[derive(Serialize)]
struct Message<'a> {
    id: u64,
    kind: &'a str,
    body: &'a str,
}

#[derive(Error, Debug)]
pub enum RunDaemonError {
    #[error("config error: {0}")]
    Config(String),

    #[error("io error: {0}")]
    Io(#[from] io::Error),

    #[error("ws api error: {0}")]
    WebSocket(#[from] tungstenite::Error),

    #[error("general error: {0}")]
    Misc(String),
}

type Result<T> = ::std::result::Result<T, RunDaemonError>;

pub fn run_call_master() -> Result<String> {
    use RunDaemonError as Error;

    // read initial configuration
    let config_file = fs::read_to_string("./priv/config.toml")?;
    let config = toml::from_str::<DaemonConfig>(&config_file)
        .map_err(|e| Error::Config(format!("err: {e:?}")))?;

    println!("sending test message to master: {}", config.controller.url);
    let url = format!("{}/test", config.controller.url);

    // generate the json message
    let test_message = Message { id: 0, kind: "test", body: "hello, world." };

    let json_blob = serde_json::to_vec(&test_message)
        .map_err(|e| Error::Misc(format!("error: {e:?}")))?;

    // load our crypto primitives
    let key_material = BASE64.decode(config.controller.privkey.as_bytes())
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
        .map_err(|e| Error::Misc(format!("req error: {e:?}")))?;

    let resp_body = resp.body_mut().read_to_string()
        .map_err(|e| Error::Misc(format!("error: {e:?}")))?;

    Ok(resp_body)
}

pub fn run_websocket_test() -> Result<String> {
    use tungstenite::{client, ClientRequestBuilder};
    use tungstenite::protocol::{frame, Message};
    use RunDaemonError as Error;

    let uri = "ws://localhost:4000/api/websocket".parse()
        .map_err(|e| Error::Misc(format!("invalid uri: {e:?}")))?;

    let ws_config = ClientRequestBuilder::new(uri)
        .with_header("x-cyrene-id", "hitomi") // TODO: hardcoded host ID
        .with_sub_protocol("x-cyrene-v1");

    let (mut socket, _response) = client::connect(ws_config)?;
    println!("connected ...");

    let msg_bytes = frame::Utf8Bytes::from_static("woah broah, woah ...");
    socket.write(Message::Text(msg_bytes))?;
    socket.flush()?;
    println!("wrote message");

    'ws: loop {
        std::thread::sleep_ms(100);
        if !socket.can_read() { continue; }

        let message = match socket.read()? {
            Message::Text(utf8_bytes) => utf8_bytes.to_string(),
            _ => panic!("unhandled message type ..."),
        };

        println!("got: {message}");
        break 'ws // exit after our echo
    }

    Err(RunDaemonError::Misc(format!("not yet implemented")))
}
