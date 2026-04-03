use bytes::{Buf, BufMut, Bytes, BytesMut};
use data_encoding::BASE64;
use mio::{Events, Interest, Token};
use mio::net::TcpStream;
use snow::{HandshakeState, TransportState};

use std::io::{self,Read, Write};

use super::{Client, ClientError, NOISE_INIT};

/// This encapsulates a simple state machine which performs a Noise KK
/// handshake based on an arbitrary amount of bytes being fed into
/// it at any given instant.
///
/// This is mostly useful in a networking context where its possible
/// a `read` call may not return a complete handshake packet in a single
/// execution and more bytes need to be read.
///
/// The intended use is to:
/// - call `consume()` until you are out of bytes
/// - in a tight loop call `try_advance()` until one of the following occurs
///   - it returns `Ok(false)` indicating more bytes are required to advance
///     to the next state ...
///
///   - it returns `Err(...)` indicating a fatal handshake failure
///
///   - you have advanced to the final `DrainResponse` state, in which case
///     you shoudl abort your read loop and consume this engine.
/// 
/// Calling `into_inner()` will error if the engine is not in the final
/// `DrainResponse` state when it is invoked. Otherwise the engine will
/// return the responder used to create this instance, along with the buffer
/// containing the response message.
/// 
/// To complete the handshake you MUST send the response buffer to the initiator
/// in its entirety, and then switch the responder into transport mode.
///
#[derive(Debug)]
pub struct HandshakeEngine {
    state: State,
    responder: HandshakeState,

    rx_buf: BytesMut,
    tx_buf: BytesMut,
}

/// The `HandshakeEngine` can be in one of the following states:
///
/// 1. `NeedPacketLen` needs to read a big endian `u16` off the wire indicating
///    the size of the incoming message from the initiator.
///
/// 2. `NeedPacketBody` needs to read `len` more bytes off the wire so it
///    can reconstruct the message from the initiator.
///
/// 3. `GenerateRequest` needs to consume the input buffer, decrypt it, and then
///    formulate an encrypted response to the initiator.
///
/// 4. `DrainResponse` is the end-state, the engine can be consumed into its
///    constituent parts which will contain the neccessary information to now
///    complete the handshake.
///
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum State {
    NeedPacketLen,
    NeedPacketBody { len: usize },
    GenerateRequest,
    DrainResponse,
}

impl HandshakeEngine {
    /// Initialize a new engine with modestly sized buffers in the initial state.
    pub fn new(responder: HandshakeState) -> Self {
        Self { 
            state: State::NeedPacketLen, responder,

            rx_buf: BytesMut::with_capacity(512),
            tx_buf: BytesMut::with_capacity(512),
        }
    }

    /// Called at any time you receive bytes from the initiator.
    ///
    /// You *MUST NOT* pass non-handshake related bytes into this engine.
    /// If the stream can interleave bytes intended for other recipients you
    /// must have some method to frame them, such that they are not passed
    /// into the handshake engine.
    ///
    /// Any excess bytes past the end of the handshake *WILL NOT BE RETURNED.*
    ///
    pub fn consume(&mut self, input: &[u8]) -> Result<(), ClientError> {
        match self.state {
            State::NeedPacketLen | State::NeedPacketBody { .. } => { /* fine */ },

            // only safe to call consume when we are in a read-context
            State::GenerateRequest | State::DrainResponse => {
                return Err(ClientError::HandshakeFail("cannot consume anymore, please drain D:".into()))
            }
        }

        self.rx_buf.put(input); Ok(())
    }

    /// After reading bytes you should periodically try to advance the state
    /// of the engine until it reaches the end-state.
    ///
    pub fn try_advance(&mut self) -> Result<bool, ClientError> {
        match self.state {
            State::NeedPacketLen => {
                if self.rx_buf.len() < 2 { return Ok(false) }

                let len = self.rx_buf.get_u16() as usize;
                self.state = State::NeedPacketBody { len };
                Ok(true) // know length of request body
            },

            State::NeedPacketBody { len } => {
                if self.rx_buf.len() < len { return Ok(false) }
                self.state = State::GenerateRequest;
                Ok(true) // have full request body
            },

            State::GenerateRequest => self.do_response(),
            State::DrainResponse => unreachable!("h/s advanced past finalization"),
        }
    }

    /// Once the engine has entered the end-state you can consume it and proceed
    /// to finalize the handshake.
    ///
    pub fn into_inner(self) -> Result<(Bytes, HandshakeState), ClientError> {
        if self.state != State::DrainResponse {
            return Err(ClientError::HandshakeFail("handshake engine finalization called prematurely".into()))
        }

        Ok((self.tx_buf.freeze(), self.responder))
    }

    /// Used by `State::GenerateRequest` to manipulate the crypto libraries
    /// handshake object to complete the challenge/response.
    ///
    fn do_response(&mut self) -> Result<bool, ClientError> {
        assert_eq!(self.state, State::GenerateRequest);

        // put initiator's message in the responder's buffer
        let mut hs_init_addl = BytesMut::zeroed(1024);
        let addl_sz = self.responder.read_message(&self.rx_buf, &mut hs_init_addl)?;
        assert_eq!(addl_sz, 0);

        // create our response ...
        let mut hs_output = BytesMut::zeroed(1024); // TODO: no guarantee this is big enough?
        let hs_sz = self.responder.write_message(&[], &mut hs_output)
            .inspect_err(|e| eprintln!("unexpected i/o error writing handshake {e:?}"))?;

        // generate a wire packet in tx_buf ...
        assert!(hs_sz < u16::MAX as usize);
        self.tx_buf.put_u16(hs_sz as u16);
        self.tx_buf.put(&hs_output[..hs_sz]);
        self.state = State::DrainResponse;

        Ok(true)
    }
}

/// Temporarily borrows a `Client` and uses its TCP stream to negotiate a Noise session.
///
pub fn perform_handshake(client: &mut Client, client_t: Token) -> Result<TransportState, ClientError> {
    println!("starting client handshake ...");

    // some loop configuration ...
    let mut events = Events::with_capacity(128);

    // setup the crypto block
    let key_controller = BASE64.decode(client.cfg.controller.pubkey.as_bytes())
        .map_err(|e| { ClientError::BadConfig(format!("failed to read controller public key: {e:?}")) })?;

    let key_daemon = BASE64.decode(client.cfg.controller.privkey.as_bytes())
        .map_err(|e| { ClientError::BadConfig(format!("failed to read daemon private key: {e:?}")) })?;

    // TODO: don't love that we need to unwrap each step ...
    let responder = snow::Builder::new(NOISE_INIT.parse()?)
        .local_private_key(&key_daemon)?
        .remote_public_key(&key_controller)?
        .build_responder()?;

    let mut hs_engine = HandshakeEngine::new(responder);

    client.conn_p.registry()
        .register(&mut client.conn_s, client_t, Interest::READABLE)
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
                State::NeedPacketLen => {
                    if !hs_engine.try_advance()? { continue 'hs }
                    continue 'state
                },

                State::NeedPacketBody { .. } => {
                    if !hs_engine.try_advance()? { continue 'hs }
                    continue 'state
                },


                State::GenerateRequest => {
                    if !hs_engine.try_advance()? { continue 'hs }
                    continue 'state
                },

                State::DrainResponse => { break 'hs },
            }
        }
    }

    // re-register as writable so we can send the handshake response ...
    let (mut hs_output_packet, responder) = hs_engine.into_inner()?;

    client.conn_p.registry()
        .reregister(&mut client.conn_s, client_t, Interest::READABLE | Interest::WRITABLE)
        .map_err(ClientError::NetIo)?;

    'hs: loop {
        client.conn_p.poll(&mut events, None).map_err(ClientError::NetIo)?;

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

fn drain_hs_close(packet: &mut Bytes, conn: &mut TcpStream) -> Result<bool, ClientError> {
    'write: loop {
        if packet.is_empty() { break 'write }

        match conn.write(packet) {
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
    
    Ok(packet.is_empty())
}

#[cfg(test)]
mod tests {
    use bytes::{Buf, BufMut, Bytes, BytesMut};
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

        let initiator = snow::Builder::new(noise_parms)
            .local_private_key(private).expect("cannot set private key")
            .remote_public_key(public).expect("cannot set public key")
            .build_initiator().expect("cannot build responder");

        initiator // output an initiator or PANIC
    }

    fn get_responder(private: &[u8], public: &[u8]) -> HandshakeState {
        let noise_parms = NOISE_INIT.parse::<NoiseParams>().expect("parse failure");

        let responder = snow::Builder::new(noise_parms)
            .local_private_key(private).expect("cannot set private key")
            .remote_public_key(public).expect("cannot set public key")
            .build_responder().expect("cannot build responder");

        responder // output a responder or PANIC
    }

    #[test]
    fn short_read_len() {
        let (k_private, k_public) = gen_keypair();
        let responder = get_responder(&k_private, &k_public);

        let mut hs = HandshakeEngine::new(responder);
        hs.consume(&[0x2A]).expect("read failed");
        let advanced = hs.try_advance().expect("advance should not error");
        assert_eq!(false, advanced);
        assert_eq!(hs.state, State::NeedPacketLen);

        hs.consume(&[0x45]).expect("read failed");
        let advanced = hs.try_advance().expect("advance should not error");
        assert_eq!(true, advanced);
        assert_eq!(hs.state, State::NeedPacketBody { len: 0x2A45 });
    }

    #[test]
    fn attempt_initiate() {
        let (r_private, r_public) = gen_keypair();
        let (i_private, i_public) = gen_keypair();

        let responder = get_responder(&r_private, &i_public);
        let mut hs = HandshakeEngine::new(responder);

        // pretend we're an initiator and write the packet like it would be
        // on the wire from `snapcon` ...
        let mut initiator = get_initiator(&i_private, &r_public);

        let mut init_buf = BytesMut::zeroed(1024); 
        let sz = initiator.write_message(&[], &mut init_buf)
            .expect("initiator could not write message ...");

        let mut resp_buf = BytesMut::with_capacity(1024);
        resp_buf.put_u16(sz as u16);
        resp_buf.put(&init_buf[..sz]);

        // consume the fake wire packet
        hs.consume(&resp_buf).expect("could not consume");
        let turn = hs.try_advance().expect("could not advance");
        assert_eq!(true, turn);
        assert_eq!(hs.state, State::NeedPacketBody { len: sz });

        let turn = hs.try_advance().expect("could not advance");
        assert_eq!(true, turn);
        assert_eq!(hs.state, State::GenerateRequest);
    }

    #[test]
    fn attempt_generate() {
        let (r_private, r_public) = gen_keypair();
        let (i_private, i_public) = gen_keypair();

        let responder = get_responder(&r_private, &i_public);
        let mut hs = HandshakeEngine::new(responder);

        // pretend we're an initiator and write the packet like it would be
        // on the wire from `snapcon` ...
        let mut initiator = get_initiator(&i_private, &r_public);
        let mut init_buf = BytesMut::zeroed(1024); 
        let sz = initiator.write_message(&[], &mut init_buf)
            .expect("initiator could not write message ...");

        let mut resp_buf = BytesMut::with_capacity(1024);
        resp_buf.put_u16(sz as u16);
        resp_buf.put(&init_buf[..sz]);

        // consume the fake wire packet
        hs.consume(&resp_buf).expect("could not consume");
        let _ = hs.try_advance().expect("could not advance");
        let _ = hs.try_advance().expect("could not advance");
        let turn = hs.try_advance().expect("could not advance");
        assert_eq!(true, turn);
        assert_eq!(hs.state, State::DrainResponse);

        let (buf, _) = hs.into_inner().expect("could not generate");
        assert!(buf.len() > 0);
    }

    #[test]
    fn attempt_transport() {
        let (r_private, r_public) = gen_keypair();
        let (i_private, i_public) = gen_keypair();

        let responder = get_responder(&r_private, &i_public);
        let mut hs = HandshakeEngine::new(responder);

        // pretend we're an initiator and write the packet like it would be
        // on the wire from `snapcon` ...
        let mut initiator = get_initiator(&i_private, &r_public);
        let mut init_buf = BytesMut::zeroed(1024); 
        let sz = initiator.write_message(&[], &mut init_buf)
            .expect("initiator could not write message ...");

        let mut resp_buf = BytesMut::with_capacity(1024);
        resp_buf.put_u16(sz as u16);
        resp_buf.put(&init_buf[..sz]);

        // consume the fake wire packet
        hs.consume(&resp_buf).expect("could not consume");
        let _ = hs.try_advance().expect("could not advance");
        let _ = hs.try_advance().expect("could not advance");
        let _ = hs.try_advance().expect("could not advance");
        let (mut buf, responder) = hs.into_inner().expect("could not generate");

        // actually write the response
        let mut init_buf = BytesMut::zeroed(1024);
        buf.advance(2); // skip the length needed for TCP frame ...
        let sz = initiator.read_message(&buf, &mut init_buf)
            .expect("initiator could not process packet");

        assert_eq!(sz, 0); // NOTE: no additional data from our HS engine ...

        // enter transport mode and verify we can use the channel
        let mut tx = initiator.into_transport_mode().expect("send could not enter transport");
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
