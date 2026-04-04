use bytes::{Buf, BufMut, BytesMut};
use data_encoding::BASE64;
use mio::{Events, Interest, Token};
use mio::net::TcpStream;
use snow::{HandshakeState, TransportState};
use tracing::{debug, info};

use std::io::{self,Read, Write};

use super::{Client, ClientError, NOISE_INIT};

/// This encapsulates a simple state machine which performs a Noise IK
/// handshake based on an arbitrary amount of bytes being fed into
/// it at any given instant. (The handshake is performed as an initiator.)
///
/// This is mostly useful in a networking context where its possible
/// a `read` call may not return a complete handshake packet in a single
/// execution and more bytes need to be read.
///
/// The intended use is to:
/// - drain `tx_buf()` and send it in its entirety to the responder
/// - call `consume()` as bytes arrive from the responder
/// - in a tight loop call `try_advance()` until one of the following occurs
///   - it returns `Ok(false)` indicating more bytes are required
///   - it returns `Err(...)` indicating a fatal handshake failure
///   - you have advanced to the final `Done` state
///
/// Calling `into_inner()` will error if the engine is not in `Done`.
/// Otherwise it returns the `HandshakeState` ready for `into_transport_mode()`.
///
#[derive(Debug)]
pub struct HandshakeEngine {
    state: State,
    initiator: HandshakeState,

    rx_buf: BytesMut,
    tx_buf: BytesMut,
}

/// The `HandshakeEngine` can be in one of the following states:
///
/// 1. `DrainRequest` (initial) — `tx_buf` holds the framed opening packet.
///    Caller sends it; `try_advance()` automatically transitions to
///    `NeedPacketLen` once `tx_buf` is empty.
///
/// 2. `NeedPacketLen` — needs a big-endian `u16` from the responder indicating
///    the size of its reply.
///
/// 3. `NeedPacketBody` — needs `len` more bytes to reconstruct the reply.
///
/// 4. `ProcessResponse` — decrypts the responder's message and completes
///    the crypto handshake.
///
/// 5. `Done` — end state; call `into_inner()` to retrieve the `HandshakeState`.
///
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum State {
    DrainRequest,
    NeedPacketLen,
    NeedPacketBody { len: usize },
    ProcessResponse,
    Done,
}

impl HandshakeEngine {
    /// Initialize a new engine, immediately writing the opening handshake
    /// packet into `tx_buf`. Returns an engine in the `DrainRequest` state.
    /// 
    /// You must exhaust `tx_buf()` by transmitting it to a Noise responder,
    /// and once done call `try_advance()` to move the engine to the next state.
    ///
    pub fn new(mut initiator: HandshakeState) -> Result<Self, ClientError> {
        let mut tx_buf = BytesMut::with_capacity(512);

        let mut msg_buf = BytesMut::zeroed(1024);
        let sz = initiator.write_message(&[], &mut msg_buf)?;

        assert!(sz < u16::MAX as usize);
        tx_buf.put_u16(sz as u16);
        tx_buf.put(&msg_buf[..sz]);

        Ok(Self {
            state: State::DrainRequest, initiator,
            rx_buf: BytesMut::with_capacity(512),
            tx_buf,
        })
    }

    /// Returns the outgoing packet buffer. Only meaningful during `DrainRequest`.
    ///
    pub fn tx_buf(&self) -> &[u8] { &self.tx_buf }

    /// Called whenever bytes arrive from the responder.
    ///
    /// You *MUST NOT* pass non-handshake related bytes into this engine.
    /// Any excess bytes past the end of the handshake *WILL NOT BE RETURNED.*
    ///
    pub fn consume(&mut self, input: &[u8]) -> Result<(), ClientError> {
        match self.state {
            State::NeedPacketLen | State::NeedPacketBody { .. } => { /* fine */ },

            // only safe to call consume when we are waiting for responder bytes
            _ => return Err(ClientError::HandshakeFail("cannot consume in current state".into())),
        }

        self.rx_buf.put(input); Ok(())
    }

    /// Attempt to advance the state machine. Returns `Ok(true)` if the state
    /// changed, `Ok(false)` if more bytes are needed, or `Err` on failure.
    ///
    pub fn try_advance(&mut self) -> Result<bool, ClientError> {
        match self.state {
            State::DrainRequest => {
                if !self.tx_buf.is_empty() { return Ok(false) }
                self.state = State::NeedPacketLen;
                Ok(true)
            },

            State::NeedPacketLen => {
                if self.rx_buf.len() < 2 { return Ok(false) }

                let len = self.rx_buf.get_u16() as usize;
                self.state = State::NeedPacketBody { len };
                Ok(true)
            },

            State::NeedPacketBody { len } => {
                if self.rx_buf.len() < len { return Ok(false) }
                self.state = State::ProcessResponse;
                Ok(true)
            },

            State::ProcessResponse => self.do_process_response(),
            State::Done => unreachable!("h/s advanced past finalization"),
        }
    }

    /// Once the engine has entered `Done` you can consume it to get the
    /// crypto engine back, configured in `transport` mode.
    ///
    pub fn into_inner(self) -> Result<TransportState, ClientError> {
        if self.state != State::Done {
            return Err(ClientError::HandshakeFail("handshake engine finalization called prematurely".into()))
        }

        Ok(self.initiator.into_transport_mode()?)
    }

    /// `ProcessResponse`: decrypt the responder's reply and complete the handshake.
    fn do_process_response(&mut self) -> Result<bool, ClientError> {
        assert_eq!(self.state, State::ProcessResponse);

        let mut resp_buf = BytesMut::zeroed(1024);
        self.initiator.read_message(&self.rx_buf, &mut resp_buf)?;
        self.state = State::Done;

        Ok(true)
    }
}

/// Temporarily borrows a `Client` and uses its TCP stream to negotiate a Noise session.
///
pub fn perform_handshake(client: &mut Client, client_t: Token) -> Result<TransportState, ClientError> {
    info!("starting client handshake ...");

    // some loop configuration ...
    let mut events = Events::with_capacity(128);

    client.conn_p.registry()
        .register(&mut client.conn_s, client_t, Interest::READABLE | Interest::WRITABLE)
        .map_err(ClientError::NetIo)?;

    // setup the crypto block
    let key_controller = BASE64.decode(client.cfg.controller.pubkey.as_bytes())
        .map_err(|e| { ClientError::BadConfig(format!("failed to read controller public key: {e:?}")) })?;

    let key_daemon = BASE64.decode(client.cfg.controller.privkey.as_bytes())
        .map_err(|e| { ClientError::BadConfig(format!("failed to read daemon private key: {e:?}")) })?;

    let initiator = snow::Builder::new(NOISE_INIT.parse()?)
        .local_private_key(&key_daemon)?
        .remote_public_key(&key_controller)?
        .build_initiator()?;

    let mut hs_engine = HandshakeEngine::new(initiator)?;

    // send the opening packet
    'hs: loop {
        client.conn_p.poll(&mut events, None).map_err(ClientError::NetIo)?;

        'ev: for event in events.iter() {
            if event.is_writable() && event.is_write_closed() {
                return Err(ClientError::UnexpectedEof("peer hungup before h/s initiated".into()))
            }

            if !event.is_writable() { continue 'ev } else { break 'ev }
        }

        let pkt = hs_engine.tx_buf().to_vec();
        let sz_w = client.conn_s.write(&pkt).map_err(ClientError::NetIo)?;
        assert_eq!(pkt.len(), sz_w);
        debug!("initiator wrote {sz_w} bytes");
        hs_engine.tx_buf.clear();
        assert!(hs_engine.try_advance()?);
        break 'hs
    }

    // read the responder's reply
    client.conn_p.registry()
        .reregister(&mut client.conn_s, client_t, Interest::READABLE)
        .map_err(ClientError::NetIo)?;

    'hs: loop {
        client.conn_p.poll(&mut events, None).map_err(ClientError::NetIo)?;

        for event in events.iter() {
            if event.is_read_closed() || event.is_write_closed() {
                return Err(ClientError::HandshakeFail("connection closed during handshake unexpectedly".into()));
            }

            if !event.is_readable() {
                return Err(ClientError::HandshakeFail("unexpected write event during handshake recv".into()))
            }

            drain_hs_open(&mut hs_engine, &mut client.conn_s)?;
        }

        'state: loop { /* pump state machine until impossible or complete ... */
            match hs_engine.state {
                State::NeedPacketLen | State::NeedPacketBody { .. } | State::ProcessResponse => {
                    if !hs_engine.try_advance()? { continue 'hs }
                    continue 'state
                },

                State::Done => { break 'hs },

                State::DrainRequest => {
                    unreachable!("unexpected drain state during responder read loop")
                },
            }
        }
    }

    let initiator = hs_engine.into_inner()?;
    debug!("peer handshake completed");
    Ok(initiator)
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

#[cfg(test)]
mod tests {
    use bytes::{BufMut, Bytes, BytesMut};
    use crate::daemon::tcp::{NOISE_INIT};
    use snow::{HandshakeState, params::NoiseParams};
    use super::{HandshakeEngine, State};

    fn gen_keypair() -> (Bytes, Bytes) {
        let noise_parms = NOISE_INIT.parse::<NoiseParams>().expect("parse failure");

        let kp = snow::Builder::new(noise_parms.clone())
            .generate_keypair().expect("could not build keypair");

        (Bytes::copy_from_slice(&kp.private), Bytes::copy_from_slice(&kp.public))
    }

    fn get_initiator(private: &[u8], public: &[u8]) -> HandshakeState {
        let noise_parms = NOISE_INIT.parse::<NoiseParams>().expect("parse failure");

        snow::Builder::new(noise_parms)
            .local_private_key(private).expect("cannot set private key")
            .remote_public_key(public).expect("cannot set public key")
            .build_initiator().expect("cannot build initiator")
    }

    fn get_responder(private: &[u8], public: &[u8]) -> HandshakeState {
        let noise_parms = NOISE_INIT.parse::<NoiseParams>().expect("parse failure");

        snow::Builder::new(noise_parms)
            .local_private_key(private).expect("cannot set private key")
            .remote_public_key(public).expect("cannot set public key")
            .build_responder().expect("cannot build responder")
    }

    /// Returns an engine in `DrainRequest` and a responder that has not yet
    /// seen any bytes.
    fn make_engine_and_responder() -> (HandshakeEngine, HandshakeState) {
        let (r_private, r_public) = gen_keypair();
        let (i_private, i_public) = gen_keypair();

        let initiator = get_initiator(&i_private, &r_public);
        let responder = get_responder(&r_private, &i_public);

        let hs = HandshakeEngine::new(initiator).expect("engine construction failed");
        assert_eq!(hs.state, State::DrainRequest);

        (hs, responder)
    }

    /// Simulates the responder receiving the engine's opening packet and
    /// returning a framed reply packet.
    fn responder_reply(hs: &HandshakeEngine, responder: &mut HandshakeState) -> BytesMut {
        // the engine's tx_buf is framed: u16 len + body
        let tx = hs.tx_buf();
        let body_len = u16::from_be_bytes([tx[0], tx[1]]) as usize;
        let body = &tx[2..2 + body_len];

        let mut tmp = BytesMut::zeroed(1024);
        let sz = responder.read_message(body, &mut tmp).expect("responder could not read opening");
        assert_eq!(sz, 0);

        let sz = responder.write_message(&[], &mut tmp).expect("responder could not write reply");

        let mut pkt = BytesMut::with_capacity(sz + 2);
        pkt.put_u16(sz as u16);
        pkt.put(&tmp[..sz]);
        pkt
    }

    #[test]
    fn new_primes_opening_packet() {
        let (_r_private, r_public) = gen_keypair();
        let (i_private, _i_public) = gen_keypair();

        let initiator = get_initiator(&i_private, &r_public);
        let hs = HandshakeEngine::new(initiator).expect("engine construction failed");

        assert_eq!(hs.state, State::DrainRequest);
        assert!(hs.tx_buf().len() > 2); // at least a u16 + some body
    }

    #[test]
    fn short_read_len() {
        let (mut hs, mut responder) = make_engine_and_responder();
        let reply = responder_reply(&hs, &mut responder);

        hs.tx_buf.clear();
        hs.try_advance().expect("drain advance failed"); // DrainRequest -> NeedPacketLen
        assert_eq!(hs.state, State::NeedPacketLen);

        // feed only one byte of the length prefix
        hs.consume(&reply[..1]).expect("consume failed");
        let advanced = hs.try_advance().expect("advance should not error");
        assert_eq!(false, advanced);
        assert_eq!(hs.state, State::NeedPacketLen);

        // feed the second byte
        hs.consume(&reply[1..2]).expect("consume failed");
        let advanced = hs.try_advance().expect("advance should not error");
        assert_eq!(true, advanced);
        let body_len = u16::from_be_bytes([reply[0], reply[1]]) as usize;
        assert_eq!(hs.state, State::NeedPacketBody { len: body_len });
    }

    #[test]
    fn attempt_process_response() {
        let (mut hs, mut responder) = make_engine_and_responder();
        let reply = responder_reply(&hs, &mut responder);

        hs.tx_buf.clear();
        hs.try_advance().expect("drain advance failed"); // -> NeedPacketLen
        hs.consume(&reply).expect("could not consume");
        let _ = hs.try_advance().expect("could not advance"); // NeedPacketLen -> NeedPacketBody
        let _ = hs.try_advance().expect("could not advance"); // NeedPacketBody -> ProcessResponse
        let turn = hs.try_advance().expect("could not advance"); // ProcessResponse -> Done
        assert_eq!(true, turn);
        assert_eq!(hs.state, State::Done);
    }

    #[test]
    fn attempt_transport() {
        let (mut hs, mut responder) = make_engine_and_responder();
        let reply = responder_reply(&hs, &mut responder);

        hs.tx_buf.clear();
        hs.try_advance().expect("drain advance failed"); // -> NeedPacketLen
        hs.consume(&reply).expect("could not consume");
        let _ = hs.try_advance().expect("could not advance");
        let _ = hs.try_advance().expect("could not advance");
        let _ = hs.try_advance().expect("could not advance");

        // enter transport mode and verify we can use the channel
        let mut tx = hs.into_inner().expect("send could not enter transport");
        let mut rx = responder.into_transport_mode().expect("recv could not enter transport");

        let mut test_packet = BytesMut::zeroed(1024);
        let sz = tx.write_message(b"hello, world", &mut test_packet)
            .expect("failed to write test packet");

        let mut recv_packet = BytesMut::zeroed(1024);
        let sz = rx.read_message(&test_packet[..sz], &mut recv_packet)
            .expect("failed to read test packet");

        assert_eq!(b"hello, world", &recv_packet[..sz]);
    }
}
