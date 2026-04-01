use crossbeam_channel::{Receiver, Sender};
use tungstenite::{client, ClientRequestBuilder};
use tungstenite::Error as WsError;
use tungstenite::protocol::{frame, CloseFrame, Message};
use ureq::{self, http::Uri};

use crate::config;
use super::proto::{self, Codec};
use super::err::*;
use super::{EventReq, EventRep, Packet};

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

pub struct WsInit {
    pub name: String,
    pub req_tx: Sender<Packet<EventReq>>,
    pub rep_tx: Sender<Packet<EventRep>>,
    pub rep_rx: Receiver<Packet<EventRep>>,
}

pub fn start_socket_thread(comms: WsInit) -> Result<Receiver<Packet<EventRep>>> {
    println!("booting web socket ...");
    let cfg = config::read_cached_file()?;

    let codec = Codec { cfg: &cfg };

    drop(comms.rep_tx); // TODO: use of unused field

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
            // nice
            let output = codec.encode_packet(event_rep)?;
            socket.write(Message::binary(output))?;
            socket.flush()?;
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
                let (nonce, ttl, json_str) = codec.decode_packet(&bytes)?;
                let app_msg = serde_json::from_str(&json_str)?;
                let packet = Packet::from_parts(nonce, ttl, app_msg);

                comms.req_tx.send(packet)
                    .inspect_err(|err| eprintln!("{err:?}"))
                    .map_err(|_| { RunError::Misc("ws->daemon submission error".into()) })?;

                continue 'ws;
            },

            _ => { eprintln!("unhandled ws frame"); continue 'ws; },
        }
    }

    Ok(comms.rep_rx)
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
