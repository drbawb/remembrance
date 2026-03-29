// TODO: imports
use data_encoding::BASE64;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
// use ed25519_dalek::{SigningKey, Signer};
use sha2::{Digest, Sha256};

use tungstenite::{client, ClientRequestBuilder};
use tungstenite::Error as WsError;
use tungstenite::protocol::{frame, CloseFrame, Message};
use ureq::{self, http::Uri};

use crate::config::{self, DaemonConfig};
use super::err::*;
use super::{EventReq, EventRep};

use std::io::{self, Cursor, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[allow(dead_code)]
pub struct WsInit {
    pub name: String,
    pub req_tx: SyncSender<EventReq>,
    pub rep_tx: SyncSender<EventRep>,
    pub rep_rx: Receiver<EventRep>,
}

pub fn start_socket_thread(comms: WsInit) -> Result<Receiver<EventRep>> {
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
        .with_header("x-cyrene-id", &comms.name) // TODO: hardcoded host ID
        .with_sub_protocol("x-cyrene-v1");

    let (mut socket, _resp) = client::client(ws_config, stream.try_clone()?)
        .map_err(|err| RunError::Misc(format!("handshake error: {err:?}")))?;

    socket.flush()?;
    stream.set_nonblocking(true)?;
    println!("connected ws client for: {}", cfg.uri_ws());

    'ws: loop {
        std::thread::sleep(Duration::from_millis(10));

        // TODO: secondary drain loop
        // drain outgoing submission queue
        if let Ok(event_rep) = comms.rep_rx.try_recv() {
            let json_str = serde_json::to_string(&event_rep)?;
            println!("encoding & signing {json_str}");
        }

        if !socket.can_read() { continue 'ws } // non-blocking

        let ws_msg_frame = match socket.read() {
            Ok(frame) => frame,
            Err(WsError::Io(e)) if e.kind() == io::ErrorKind::WouldBlock => { continue 'ws },
            Err(err) => return Err(RunError::from(err)),
        };

        match ws_msg_frame {
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

            Message::Binary(bytes) => {
                let json_str = decode_packet(&cfg, &bytes)?;
                let app_msg = serde_json::from_str(&json_str)?;

                comms.req_tx.send(app_msg)
                    .inspect_err(|err| eprintln!("{err:?}"))
                    .map_err(|_| { RunError::Misc("ws->daemon submission error".into()) })?;

                continue 'ws;
            },

            _ => { eprintln!("unhandled ws frame"); continue 'ws; },
        }
    }

    Ok(comms.rep_rx)
}

fn decode_packet(cfg: &DaemonConfig, buf: &[u8]) -> Result<String> {
    use byteorder::{NetworkEndian as NE, ReadBytesExt, WriteBytesExt};

    // TODO: cache base 64 decode result
    let key_material = BASE64.decode(cfg.controller.pubkey.as_bytes())
        .expect("failed to decode ed25519 private key");

    let vk_bytes: &[u8; 32] = key_material.as_slice().try_into()
        .expect(&format!("invalid key length (have: {}, want: 32)", key_material.len()));

    let vk = VerifyingKey::from_bytes(vk_bytes)
        .map_err(|err| { RunError::Misc(format!("bad verifier key: {err:?}")) })?;

    // read packet header
    let mut rdr = Cursor::new(buf);

    let nonce = rdr.read_u128::<NE>()?;
    let ttl   = rdr.read_u64::<NE>()?;
    let sig_l = rdr.read_u16::<NE>()?;
    let pay_l = rdr.read_u16::<NE>()?;
    let flags = rdr.read_u32::<NE>()?;

    // early header verification
    if flags != 0x0000 { 
        return Err(RunError::Misc("auth: not expecting flags yet ??".into())) 
    }

    if sig_l != 64 {
        return Err(RunError::Misc(format!("auth: unexpected signature length {sig_l}")))
    }

    // check packet expiration 
    let expiry_t = UNIX_EPOCH + Duration::from_secs(ttl);

    if SystemTime::now() > expiry_t {
        return Err(RunError::Misc("packet has expired ...".into()))
    }

    // check packet signature
    println!("length (buf: {}, sig: {sig_l}, payload: {pay_l})", buf.len());
    let mut sig_buf = [0u8; 64];
    rdr.read_exact(&mut sig_buf[..])?;

    // TODO: check nonce

    let mut total = pay_l as i32;
    let mut hasher = Sha256::new();

    // hash fixed blocks of payload until we can't
    while total > 32 {
        let mut buf = [0u8; 32];
        rdr.read_exact(&mut buf)?; total -= 32;
        hasher.update(&buf[..]);
    }

    // hash last sub-block
    if total > 0 {
        let mut buf = [0u8; 32];
        let n = rdr.read(&mut buf)? as i32;

        if n < total { // short read; error
            return Err(RunError::Misc(format!("short read (have: {n}, want: {total})")))
        }

        if n > total { // long read; warning
            eprintln!("warning: unused bytes after payload?")
        }

        hasher.update(&buf[..total as usize]);
    }

    let pl_digest = hasher.finalize();

    let sig_subpacket = {
        let mut packet_sig_b = [0u8; 128];
        let mut sig_w = Cursor::new(&mut packet_sig_b[..]);
        sig_w.write_u128::<NE>(nonce)?;
        sig_w.write_u64::<NE>(ttl)?;
        sig_w.write(&pl_digest[0..32])?;
        assert!(sig_w.position() == 56); drop(sig_w);

        packet_sig_b
    };

    let signature = Signature::from_bytes(&sig_buf);
    vk.verify(&sig_subpacket[..56], &signature)
        .map_err(|_| { RunError::Misc(format!("verification failed")) })?;

    let mut output = String::new(); rdr.set_position(96);
    rdr.read_to_string(&mut output)?;

    Ok(output) // TODO: what do we return?
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
