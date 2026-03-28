use tungstenite::{client, ClientRequestBuilder};
use tungstenite::Error as WsError;
use tungstenite::protocol::{frame, CloseFrame, Message};
use ureq::{self, http::Uri};

use crate::config;
use super::err::*;
use super::{EventReq, EventRep};

use std::io;
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::mpsc::{Receiver, SyncSender};
use std::time::Duration;

pub struct WsInit {
    pub req_tx: SyncSender<EventReq>,
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

        // eprintln!("ws debug: {message}");
        if message.contains("summoned") {
            if let Err(msg) = comms.req_tx.send(EventReq::Ping { msg: message }) {
                eprintln!("ws -x-> daemon: {msg:?}");
            }
        }

        if false { break 'ws }
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
