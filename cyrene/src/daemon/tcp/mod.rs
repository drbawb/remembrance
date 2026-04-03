use bytes::BytesMut;
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use mio::{Events, Interest, Poll, Token, Waker};
use mio::net::TcpStream;
use thiserror::Error;
use tracing::{info, error};

use crate::config::{self, DaemonConfig};
use crate::daemon::Snooze;
use crate::daemon::tcp::wire::PacketError;
use super::err;
use super::{EventReq, EventRep, Packet};
use wire::PacketEngine;

use std::io;
use std::net::SocketAddr;

mod hs;
mod wire;

const NOISE_INIT: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

///
/// The parameter-set needed to setup a new TCP client for a daemon.
/// `req_tx` is used to send incoming packets to the daemon, and `rep_tx`
/// can be used by the daemon to send outgoing packets back through the
/// socket.
///
/// `rep_rx` is owned by the client and is used to receive the outgoing
/// packets and transmit them over the wire; but we maintain a copy of
/// the `rep_tx` sender so it can be cloned (again) in case the daemon
/// needs to hot reload, etc.
///
#[allow(dead_code)] // TODO: name & rep_tx
#[derive(Debug)]
pub struct ClientInit {
    pub name: String,
    pub req_tx: Sender<Packet<EventReq>>,
    pub rep_tx: Sender<Packet<EventRep>>,
    pub rep_rx: Receiver<Packet<EventRep>>,
    pub waker: Snooze,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("configuration error: {0}")]
    BadConfig(String),

    #[error("crypto error: {0}")]
    BadCrypto(#[from] snow::Error),

    #[error("de/serialization failure: {0}")]
    CodecError(#[from] wire::PacketError),

    #[error("handshake error: {0}")]
    HandshakeFail(String),

    #[error("error reading socket: {0}")]
    NetIo(io::Error),

    #[error("connection was not cleanly shutdown: {0}")]
    UnexpectedEof(String),

    #[error("runtime error: {0}")]
    DaemonErr( #[from] err::RunError) // TODO: eliminate this From<_>
}

///
/// This is a TCP client used to send bidirectional communications between a
/// `cyrene` daemon instance and its configured controller. The communications
/// are authenticated and encrypted using a pre-shared cv25519 key and the
/// `snow` library.
///
pub struct Client {
    cfg: DaemonConfig,
    comms: ClientInit,
    token: Token,

    conn_p: Poll,
    conn_s: TcpStream,

    tx_buf: BytesMut,
}

impl Client {
    pub fn new(comms: ClientInit) -> Result<Self, ClientError> {
        info!("connecting to controller ...");
        let cfg = config::read_cached_file()?;
        let conn_p = Poll::new().map_err(ClientError::NetIo)?;

        let addr = cfg.controller.urn.parse::<SocketAddr>().map_err(|e| {
            let msg = format!("could not parse urn from config: {e:?}");
            ClientError::BadConfig(msg)
        })?;

        info!("opening socket to {addr:?} ...");
        let conn_s = TcpStream::connect(addr).map_err(ClientError::NetIo)?;
        let tx_buf = BytesMut::with_capacity(128 * 1024);

        Ok(Self {
            token: Token(0),

            cfg, comms,
            conn_p, conn_s,
            tx_buf,
        })
    }

    fn register_writable(&mut self, is_empty: bool) -> Result<(), ClientError> {
        let interest = 
            if is_empty { Interest::READABLE } 
            else        { Interest::READABLE | Interest::WRITABLE };

        self.conn_p.registry()
            .reregister(&mut self.conn_s, self.token, interest)
            .map_err(ClientError::NetIo)?;

        Ok(())
    }
}

#[inline(always)]
fn err_eof<T>(msg: String) -> Result<T, ClientError> {
    Err(ClientError::UnexpectedEof(msg))
}

///
/// Once a `Client` has been configured this starts an event loop which will
/// manage the bidirectional TCP stream internally. This will block indefinitely
/// (until a fatal error is encountered) and is intended to be run inside its
/// own thread.
///
/// The event loop will begin by performing a `Noise` handshake which provides
/// encrypted and authenticated transport using the pre-configured identity
/// of the controller. If the handshake is successful, indicating that the
/// controller had the expected private key, then this function resumes control
/// and begins processing messages as specified in `PROTO.md` of the `remembrance`
/// repository.
///
/// Interacting with this event loop is done by sending/receiving messages on
/// the channels which were passed in the original `ClientInit` block when
/// the client was created.
///
#[allow(unused_labels)]
pub fn client_event_loop(mut client: Client) -> Result<(), ClientError> {
    // event loop configuration
    let mut events = Events::with_capacity(128);
    let client_t = client.token; // NOTE: you may be tempted, but you need this ...

    // run the event loop to settle the initial Noise handshake ...
    let crypto = hs::perform_handshake(&mut client, client_t)?;
    let mut engine = PacketEngine::new(crypto);

    // then do the real business ...
    info!("starting client event loop ...");
    assert!(client.tx_buf.is_empty());

    client.conn_s.set_nodelay(true).map_err(ClientError::NetIo)?;

    client.conn_p.registry()
        .reregister(&mut client.conn_s, client_t, Interest::READABLE)
        .map_err(ClientError::NetIo)?;

    // schedule the daemon to wake us up
    let waker = Waker::new(client.conn_p.registry(), Token(1))
        .map_err(ClientError::NetIo)?;

    client.comms.waker.reset(waker);

    'main: loop {
        if client.tx_buf.is_empty() {
            match client.comms.rep_rx.try_recv() {
                Ok(msg) => {
                    engine.write_packet(msg)?;
                    engine.drain_write(&mut client.conn_s)?;
                    client.register_writable(engine.tx_buf_empty())?;
                },

                Err(TryRecvError::Empty) => {/* this is fine */},
                Err(err) => return err_eof(format!("reply channel closed unexpectedly: {err:?}")),
            };
        }

        'push: loop {
            let next_packet = engine.drain_queue().pop_front();
            if next_packet.is_none() { break 'push }

            if let Some(p) = next_packet
            && let Err(err) = client.comms.req_tx.send(p) {
                return err_eof(format!("request channel closed unexpectedly: {err:?}"));
            }
        }

        // TODO: deregister & recreate a TCP stream internally instead of crashing the thread ...
        client.conn_p.poll(&mut events, None).map_err(ClientError::NetIo)?;

        for event in events.iter() {
            match event.token() {
                Token(0) => { /* socket activity */ },
                Token(1) => { /* daemon wakeup   */           continue 'main },
                Token(n) => { error!("unknown token {n}"); continue 'main }
            }

            if event.is_read_closed() || event.is_write_closed() {
                return err_eof("socket was closed without clean disconnect notice D:".into());
            }

            if event.is_readable() { 
                engine.drain_read(&mut client.conn_s)?; 
                match engine.try_parse() {
                    Ok(_) => { /* fine */ },

                    Err((PacketError::Crypto(e),_)) => { return Err(e.into()) },
                    _ => { /* fine for now */ }
                }
            }

            if event.is_writable() { 
                engine.drain_write(&mut client.conn_s)?;
                client.register_writable(engine.tx_buf_empty())?;
            }
        }
    }
}
