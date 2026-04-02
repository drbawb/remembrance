use bytes::{Buf, BufMut, BytesMut};
use crossbeam_channel::{Receiver, Sender, TryRecvError};
use data_encoding::BASE64;
use mio::{Events, Interest, Poll, Token};
use mio::net::TcpStream;
use snow::TransportState;
use thiserror::Error;

use crate::config::{self, DaemonConfig};
use crate::daemon::msg::CorrelationId;
use super::err;
use super::{EventReq, EventRep, Packet};

use std::io::{self,Read, Write};
use std::net::SocketAddr;
use std::time::Duration;

static NOISE_INIT: &str = "Noise_KK_25519_ChaChaPoly_BLAKE2s";

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
#[derive(Debug)]
pub struct ClientInit {
    pub name: String,
    pub req_tx: Sender<Packet<EventReq>>,
    pub rep_tx: Sender<Packet<EventRep>>,
    pub rep_rx: Receiver<Packet<EventRep>>,
}

#[derive(Error, Debug)]
pub enum ClientError {
    #[error("configuration error: {0}")]
    BadConfig(String),

    #[error("crypto error: {0}")]
    BadCrypto(#[from] snow::Error),

    #[error("de/serialization failur: {0}")]
    CodecError(#[from] serde_json::Error),

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
///
pub struct Client {
    cfg: DaemonConfig,
    comms: ClientInit,
    token: Token,

    conn_p: Poll,
    conn_s: TcpStream,

    rx_buf: BytesMut,
    tx_buf: BytesMut,
}

impl Client {
    pub fn new(comms: ClientInit) -> Result<Self, ClientError> {
        println!("connecting to controller ...");
        let cfg = config::read_cached_file()?;
        let conn_p = Poll::new().map_err(|e| ClientError::NetIo(e))?;

        let addr = cfg.controller.urn.parse::<SocketAddr>().map_err(|e| { 
            let msg = format!("could not parse urn from config: {e:?}");
            ClientError::BadConfig(msg)
        })?;

        println!("opening socket to {addr:?} ...");
        let conn_s = TcpStream::connect(addr).map_err(|e| ClientError::NetIo(e))?;
        let rx_buf = BytesMut::with_capacity(128 * 1024);
        let tx_buf = BytesMut::with_capacity(128 * 1024);

        Ok(Self {
            token: Token(0),

            cfg, comms,
            conn_p, conn_s,
            rx_buf, tx_buf
        })
    }

    fn drain_read(&mut self) -> Result<usize, ClientError> {
        let mut bytes_read = 0;
        let mut buf = BytesMut::zeroed(2048);

        'drain: loop {
            match self.conn_s.read(&mut buf) {
                Ok(0) => { break 'drain },

                Ok(sz) => {
                    bytes_read += sz;
                    self.rx_buf.put(&buf[..sz]);
                    continue 'drain
                },

                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted { continue 'drain }
                    if e.kind() == io::ErrorKind::WouldBlock  { break 'drain }
                    return Err(ClientError::NetIo(e));
                },
            }
        }

        Ok(bytes_read)
    }

    fn drain_write(&mut self) -> Result<usize, ClientError> {
        if self.tx_buf.is_empty() { return Ok(0) }

        let mut bytes_written = 0;

        'drain: loop {
            match self.conn_s.write(&mut self.tx_buf) {
                Ok(0) => { break 'drain },

                Ok(sz) => {
                    bytes_written += sz; 
                    self.tx_buf.advance(sz);
                    continue 'drain 
                },

                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted { continue 'drain }
                    if e.kind() == io::ErrorKind::WouldBlock  { break 'drain }
                    return Err(ClientError::NetIo(e));
                },
            }
        }

        // TODO: cache/debounce this? not sure how expensive it is ...
        if self.tx_buf.remaining() > 0 {
            self.conn_p.registry()
                .reregister(&mut self.conn_s, self.token, Interest::READABLE | Interest::WRITABLE)
                .map_err(|e| ClientError::NetIo(e))?;
        } else {
            self.conn_p.registry()
                .reregister(&mut self.conn_s, self.token, Interest::READABLE)
                .map_err(|e| ClientError::NetIo(e))?;
        }

        Ok(bytes_written)
    }

    fn debug_packet<T: Buf>(mut buf: T) {
        if buf.remaining() < 32 { return; }

        println!("---");
        println!("nonce [{:016x}]", buf.get_u128());
        println!("ttl   [{:08x}]", buf.get_u64());
        println!("flags [{:04x}]", buf.get_u32());
        println!("rs    [{:02x}] len [{:02x}]", buf.get_u16(), buf.get_u16());
        println!("---");
    }

    fn write_packet(
        &mut self, 
        crypto: &mut TransportState, 
        packet: Packet<EventRep>) -> Result<usize, ClientError> {

        let json_buf = serde_json::to_string(&packet.msg)?;

        if json_buf.len() > (u16::MAX - 32) as usize {
            todo!("need to set continuation flag")
        }

        // write header
        self.tx_buf.put_u128(packet.nonce.0);
        self.tx_buf.put_u64(packet.ttl);
        self.tx_buf.put_u32(0 /* flags */); // TODO: packet continuation
        self.tx_buf.put_u16(0 /* rsvd */);

        // write encrypted message
        let mut packet_buf = BytesMut::zeroed(64 * 1024); // TODO: what size?
        let sz = crypto.write_message(json_buf.as_bytes(), &mut packet_buf)?;

        assert!(sz < (u16::MAX - 32) as usize);
        self.tx_buf.put_u16(sz as u16);
        self.tx_buf.put(&packet_buf[..sz]);

        Ok(sz + 32)
    }

    fn try_recv_packet(&mut self, crypto: &mut TransportState) -> Result<Option<Packet<EventReq>>, ClientError> {
        // need at least a full packet header:
        if self.rx_buf.len() < 32 { return Ok(None) }

        // read the header ...
        let mut rx = self.rx_buf.clone();
        let nonce = rx.get_u128();
        let ttl = rx.get_u64();
        let flags = rx.get_u32();
        let _rsvd = rx.get_u16();
        let len = rx.get_u16() as usize;

        // TODO: process continuation flag (aka buffers in your buffers)
        if (flags & 0x1) != 0 {
            todo!("continuation packet received & cannot process D:")
        }

        // don't have the full packet assembled yet:
        if self.rx_buf.len() < len { return Ok(None) }

        // consume this packet from the receiver buffer
        println!("rx_buf: {}, need: {}", self.rx_buf.len(), len);
        Self::debug_packet(self.rx_buf.clone());
        self.rx_buf.advance(32); // skip the header
        let packet_bytes = self.rx_buf.split_to(len);
        
        // decrypt it w/ noise
        let mut packet_buf = BytesMut::zeroed(64 * 1024); // TODO: what size?
        let sz = crypto.read_message(&packet_bytes, &mut packet_buf)
            .map_err(|e| ClientError::BadCrypto(e))?;

        // TODO: check nonce/ttl
        println!("decrypted {sz} bytes ...");
        let event_req = serde_json::from_reader(&packet_buf[..sz])?;

        Ok(Some(Packet {
            nonce: CorrelationId(nonce), 
            ttl: ttl,
            len: Some(sz), 
            msg: event_req,
        }))
    }
}

#[inline(always)]
fn err_eof<T>(msg: String) -> Result<T, ClientError> {
    Err(ClientError::UnexpectedEof(msg))
}

#[allow(unused_labels)]
pub fn client_event_loop(mut client: Client) -> Result<(), ClientError> {
    // event loop configuration
    let mut events = Events::with_capacity(128);
    let client_t = client.token; // NOTE: you may be tempted, but you need this ...
    
    // run the event loop to settle the initial Noise handshake ...
    let mut crypto = perform_handshake(&mut client, client_t)?;

    // then do the real business ...
    println!("starting client event loop ...");
    assert_eq!(true, client.tx_buf.is_empty());
    assert_eq!(true, client.rx_buf.is_empty());

    client.conn_p.registry()
        .reregister(&mut client.conn_s, client_t, Interest::READABLE)
        .map_err(|e| ClientError::NetIo(e))?;

    let timeout = Duration::from_millis(100);

    'main: loop {
        if client.tx_buf.is_empty() {
            match client.comms.rep_rx.try_recv() {
                Ok(msg) => {
                    let sz_in = client.write_packet(&mut crypto, msg)?;
                    println!("encoded {sz_in} bytes");

                    let sz_out = client.drain_write()?;
                    println!("wrote {sz_out} bytes");
                },

                Err(TryRecvError::Empty) => {/* this is fine */},
                Err(err) => return err_eof(format!("reply channel closed unexpectedly: {err:?}")),
            };
        }

        if !client.rx_buf.is_empty() {
            if let Some(packet) = client.try_recv_packet(&mut crypto)? {
                if let Err(err) = client.comms.req_tx.send(packet) {
                    return err_eof(format!("request channel closed unexpectedly: {err:?}"));
                }
            }
        }

        client.conn_p.poll(&mut events, Some(timeout)).map_err(|e| ClientError::NetIo(e))?;

        for event in events.iter() {
            if event.is_read_closed() || event.is_write_closed() {
                return err_eof(format!("socket was closed without clean disconnect notice D:"));
            }

            if event.is_readable() {
                let sz = client.drain_read()?;
                println!("read  {sz} bytes");
            }

            if event.is_writable() {
                let sz = client.drain_write()?;
                println!("wrote {sz} bytes");
            }
        }
    }
}

pub fn perform_handshake(client: &mut Client, client_t: Token) -> Result<TransportState, ClientError> {
    println!("starting client handshake ...");

    // some loop configuration ...
    let mut events = Events::with_capacity(128);

    // setup the crypto block
    let key_controller = BASE64.decode(client.cfg.controller.pubkey.as_bytes())
        .map_err(|e| { ClientError::BadConfig(format!("failed to read controller public key: {e:?}")) })?;

    let key_daemon = BASE64.decode(client.cfg.controller.privkey.as_bytes())
        .map_err(|e| { ClientError::BadConfig(format!("failed to read daemon private key: {e:?}")) })?;

    let mut hs_engine = HandshakeEngine::new();

    // TODO: don't love that we need to unwrap each step ...
    let mut responder = snow::Builder::new(NOISE_INIT.parse()?)
        .local_private_key(&key_daemon)?
        .remote_public_key(&key_controller)?
        .build_responder()?;

    client.conn_p.registry()
        .register(&mut client.conn_s, client_t, Interest::READABLE)
        .map_err(|e| ClientError::NetIo(e))?;

    'hs: loop {
        client.conn_p.poll(&mut events, None).map_err(|e| ClientError::NetIo(e))?;

        for event in events.iter() {
            if event.is_read_closed() || event.is_write_closed() {
                return Err(ClientError::HandshakeFail("connection closed during handshake unexpectedly".into()));
            }

            if !event.is_readable() {
                return Err(ClientError::HandshakeFail("unexpected write event during handshake recv".into()))
            }

            drain_hs_open(&mut hs_engine, &mut client.conn_s)?;
        }

        'state: loop {
            match hs_engine.state {
                State::NeedPacketLen => {
                    if !hs_engine.try_advance()? { continue 'hs }
                    continue 'state
                },

                State::NeedPacketBody { .. } => {
                    if !hs_engine.try_advance()? { continue 'hs }
                    continue 'state
                },

                State::DrainPacketResp { .. } => { break 'hs },
            }
        }
    }

    // read data packet
    let hs_init_packet = hs_engine.into_inner()?;

    // put initiator's message in the responder's buffer
    let mut hs_init_addl = BytesMut::with_capacity(1024);
    responder.read_message(&hs_init_packet, &mut hs_init_addl)?;
    assert_eq!(hs_init_addl.len(), 0);

    // create our response ...
    let mut hs_output = BytesMut::zeroed(1024);
    let hs_sz = responder.write_message(&[], &mut hs_output).inspect_err(|e| eprintln!("wtf? {e:?}"))?;
    assert!(hs_sz < u16::MAX as usize);

    let mut hs_output_packet = BytesMut::with_capacity(hs_sz + 2);
    hs_output_packet.put_u16(hs_sz as u16);
    hs_output_packet.put(&hs_output[..hs_sz]);
    drop(hs_output);

    client.conn_p.registry()
        .reregister(&mut client.conn_s, client_t, Interest::READABLE | Interest::WRITABLE)
        .map_err(|e| ClientError::NetIo(e))?;

    'hs: loop {
        client.conn_p.poll(&mut events, None).map_err(|e| ClientError::NetIo(e))?;

        for event in events.iter() {
            if event.is_read_closed() || event.is_write_closed() {
                return Err(ClientError::HandshakeFail("connection closed during handshake unexpectedly".into()));
            }

            if !event.is_writable() {
                return Err(ClientError::HandshakeFail("unexpected read event during handshake transmit".into()))
            }

            if drain_hs_close(&mut hs_output_packet, &mut client.conn_s)? { break 'hs }
        }
    }

    Ok(responder.into_transport_mode()?)
}

fn drain_hs_open(hs: &mut HandshakeEngine, conn: &mut TcpStream) -> Result<(), ClientError> {
    let mut buf = [0u8; 2048];

    loop {
        match conn.read(&mut buf) {
            Ok(0) => {
                return Err(ClientError::UnexpectedEof("could not read handshake from socket ...".into()))
            },

            Ok(sz) => hs.consume(&buf[..sz])?,

            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted { return Ok(()) }
                if e.kind() == io::ErrorKind::WouldBlock { return Ok(()) }
                return Err(ClientError::NetIo(e));
            }
        }
    }
}

fn drain_hs_close(packet: &mut BytesMut, conn: &mut TcpStream) -> Result<bool, ClientError> {
    'write: loop {
        if packet.len() <= 0 { break 'write }

        match conn.write(&packet) {
            Ok(0) => {
                return Err(ClientError::UnexpectedEof("could not write handshake to socket ...".into()))
            },

            Ok(sz) => { packet.advance(sz); continue 'write }

            Err(e) => {
                if e.kind() == io::ErrorKind::Interrupted { continue 'write }
                if e.kind() == io::ErrorKind::WouldBlock  { break 'write }
                return Err(ClientError::NetIo(e));
            },
        }
    }
    
    Ok(packet.len() <= 0)
}

#[derive(Debug)]
struct HandshakeEngine {
    state: State,
    buf: BytesMut,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum State {
    NeedPacketLen,
    NeedPacketBody { len: usize },
    DrainPacketResp { len: usize },
}

impl HandshakeEngine {
    pub fn new() -> Self {
        Self { state: State::NeedPacketLen, buf: BytesMut::new() }
    }

    pub fn consume(&mut self, input: &[u8]) -> Result<(), ClientError> {
        if let State::DrainPacketResp { .. }= self.state { 
            return Err(ClientError::HandshakeFail(format!("cannot consume anymore, please drain D:")))
        }

        self.buf.put(input); Ok(())
    }

    pub fn try_advance(&mut self) -> Result<bool, ClientError> {
        match self.state {
            State::NeedPacketLen => {
                if self.buf.len() < 2 { return Ok(false) }

                let len = self.buf.get_u16() as usize;
                self.state = State::NeedPacketBody { len };
                return Ok(true)
            },

            State::NeedPacketBody { len } => {
                if self.buf.len() < len { return Ok(false) }
                self.state = State::DrainPacketResp { len };
                return Ok(true)
            },

            State::DrainPacketResp { .. } => { return Ok(false) }
        }
    }

    pub fn into_inner(self) -> Result<BytesMut, ClientError> { 
        match self.state {
            State::DrainPacketResp { len } => {
                assert_eq!(len, self.buf.len()); Ok(self.buf)
            },

            _ => Err(ClientError::HandshakeFail("handshake engine reclaimed but not in final state!?".into()))
        }
    }

    // fn fail_io(io_err: io::Error) -> ClientError {
    //     ClientError::HandshakeFail(format!("handshake i/o err: {io_err:?}"))
    // }
}
