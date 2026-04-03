use crate::CorrelationId;
use crate::daemon::msg::Packet;

use blinkedblist::List;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use serde::{Serialize, de::DeserializeOwned};
use serde_json;
use snow::TransportState;
use thiserror::Error;
use tracing::{info};

use std::io;

const LEN_HEADER: usize = 32;

#[derive(Debug, Error)]
pub enum PacketError {
    #[error("crypto engine error: {0}")]
    Crypto(#[from] snow::Error),

    #[error("packet decode failure: {0}")]
    Decode(#[from] serde_json::Error),

    #[error("error reading packet from wire: {0}")]
    Io(#[from] io::Error),
}

type PacketResult<T> = Result<T, PacketError>;

pub struct PacketEngine<T> {
    rx_buf: BytesMut,
    pkt_list: List<Packet<T>>,
}

impl<T> PacketEngine<T> where T: DeserializeOwned {
    /// Constructs a new packet parsing engine with variably sized storage
    /// for storing a queue of packets.
    ///
    /// The internal buffer is pre-allocated large enough for one packet
    /// to be received *at maximum length* with no additional allocations,
    /// but continuing to consume bytes from additional packets via `drain_read`
    /// without calling `try_parse` in-between will grow the buffer indefinitely.
    ///
    /// Calling `try_parse` will drain the incoming buffer and attempt to parse
    /// it as a packet according to the type specified when the packet engine
    /// was created. Successfully decoded packets will be placed on a queue, and
    /// the number of such packets placed on the queue will be returned to the caller.
    ///
    pub fn new() -> PacketEngine<T> {
        Self {
            rx_buf: BytesMut::with_capacity(64 * 1024),
            pkt_list: List::new(), // TODO: blinkedblist ;; with_capacity
        }
    }

    /// Consumes bytes from the reader until the reader returns `WouldBlock`
    /// *or* some other error. If the reader produces a 0-sized read, or if
    /// the reader returns `WouldBlock`, the number of bytes read up to this
    /// point is returned.
    ///
    pub fn drain_read<R>(&mut self, mut reader: R) -> PacketResult<usize>
    where R: io::Read {
        let mut bytes_read = 0;
        let mut io_buf = [0u8; 2048];

        'drain: loop {
            match reader.read(&mut io_buf) {
                Ok(0) => { break 'drain },

                Ok(sz) => {
                    bytes_read += sz;
                    self.rx_buf.put(&io_buf[..sz]);
                    continue 'drain
                },

                Err(e) => {
                    if e.kind() == io::ErrorKind::Interrupted { continue 'drain }
                    if e.kind() == io::ErrorKind::WouldBlock  { break 'drain }
                    return Err(e.into())
                },
            }
        }

        Ok(bytes_read)
    }

    /// Checks if the `rx_buf` contains a full packet header along with all the
    /// described payload bytes. If so that packet is consumed from the buffer
    /// and stored in an internal `pkt_list` for later retrieval.
    ///
    /// If the failure returned is of the `PacketError::Framing` or `PacketError::Crytpo`
    /// kind it is likely not possible to continue using this engine, as the
    /// crypto engine's internal state may be irrecoverably corrupted. Upon receiving
    /// either of these errors the caller must take corrective actions to reconnect
    /// or resynchornize the underlying stream, and then create a new packet engine.
    ///
    /// If the failure returned is of the `PacketError::Decode` kind it is generally
    /// safe to continue using the packet engine, as this indicates the payload
    /// was decrypted correctly, but was not able to be parsed as the type 
    /// specified by the caller.
    ///
    /// Note that there may be additional packets in the stream if an error is
    /// returned, and you must continue to call `try_parse` until 0 packets are
    /// processed to fully drain the queue ...
    ///
    pub fn try_parse(&mut self, crypto: &mut TransportState) -> Result<usize, (PacketError, usize)> {
        let mut num_processed = 0;

        loop {
            // need at least a full packet header:
            if self.rx_buf.len() < LEN_HEADER { return Ok(num_processed) }

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
            if rx.len() < len { return Ok(num_processed) }

            // consume this packet from the receiver buffer
            // Self::debug_packet(self.rx_buf.clone());
            self.rx_buf.advance(LEN_HEADER); // skip the header
            let packet_bytes = self.rx_buf.split_to(len);

            // decrypt it w/ noise
            let mut packet_buf = BytesMut::zeroed(64 * 1024); // TODO: what size?
            let sz = crypto.read_message(&packet_bytes, &mut packet_buf)
                .map_err(|e| (PacketError::Crypto(e), num_processed))?;

            // TODO: check nonce/ttl
            let packet_msg = serde_json::from_reader(&packet_buf[..sz])
                .map_err(|e| (PacketError::Decode(e), num_processed))?;

            let packet_t = Packet {
                nonce: CorrelationId(nonce),
                ttl,
                len: Some(sz),
                msg: packet_msg,
            };

            self.pkt_list.push_back(packet_t); num_processed += 1
        }
    }

    // TODO: would like to return a drain iterator from the front ...
    pub fn drain_queue(&mut self) -> &mut List<Packet<T>> { &mut self.pkt_list }

    #[allow(dead_code)]
    fn debug_packet<B: Buf>(mut buf: B) {
        if buf.remaining() < LEN_HEADER { return; }

        info!("---");
        info!("nonce [{:016x}]", buf.get_u128());
        info!("ttl   [{:08x}]", buf.get_u64());
        info!("flags [{:04x}]", buf.get_u32());
        info!("rs    [{:02x}] len [{:02x}]", buf.get_u16(), buf.get_u16());
        info!("---");
    }
}

/// Encrypts & formats a reply packet for the wire, returning a byte-array which
/// can be used to send the packet onto the wire ...
///
pub fn write_packet<T>(crypto: &mut TransportState, packet: Packet<T>) -> PacketResult<Bytes>
where T: Serialize {

    let json_buf = serde_json::to_string(&packet.msg)?;

    if json_buf.len() > (u16::MAX as usize - LEN_HEADER) {
        todo!("need to set continuation flag")
    }

    let mut buf = BytesMut::with_capacity(LEN_HEADER + json_buf.len());

    // write header
    buf.put_u128(packet.nonce.0);
    buf.put_u64(packet.ttl);
    buf.put_u32(0 /* flags */); // TODO: packet continuation
    buf.put_u16(0 /* rsvd */);

    // write encrypted message
    let mut packet_buf = BytesMut::zeroed(64 * 1024); // TODO: what size?
    let sz = crypto.write_message(json_buf.as_bytes(), &mut packet_buf)?;

    assert!(sz < (u16::MAX as usize - LEN_HEADER));
    buf.put_u16(sz as u16);
    buf.put(&packet_buf[..sz]);

    Ok(buf.freeze())
}

#[cfg(test)]
mod tests {
    use crate::daemon::msg::{CorrelationId, EventReq, Packet};
    use crate::daemon::tcp::wire::LEN_HEADER;
    use crate::daemon::tcp::{NOISE_INIT};
    use super::{write_packet, PacketEngine};

    use bytes::Bytes;
    use snow::{HandshakeState, TransportState};
    use snow::params::NoiseParams;
    
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

    fn get_transport_peers() -> (TransportState, TransportState) {
        let (r_private, r_public) = gen_keypair();
        let (i_private, i_public) = gen_keypair();

        let mut responder = get_responder(&r_private, &i_public);
        let mut initiator = get_initiator(&i_private, &r_public);

        let mut init_buf = [0u8; 2048];
        let sz = initiator.write_message(&[], &mut init_buf)
            .expect("initiator could not write challenge");

        let mut resp_buf = [0u8; 2048];
        responder.read_message(&init_buf[..sz], &mut resp_buf)
            .expect("responder could not read challenge");

        let sz = responder.write_message(&[], &mut resp_buf)
            .expect("responder could not write response");

        let sz = initiator.read_message(&resp_buf[..sz], &mut init_buf)
            .expect("initiator could not read response");

        assert_eq!(sz, 0);

        // enter transport mode and verify we can use the channel
        let tx = initiator.into_transport_mode().expect("send could not enter transport");
        let rx = responder.into_transport_mode().expect("recv could not enter transport");

        (tx, rx)
    }
    
    fn fake_packet() -> Packet<EventReq> {
        let msg = EventReq::Ping { msg: "test".into() };

        Packet {
            nonce: CorrelationId(0),
            ttl: 0,
            len: None,
            msg: msg,
        }
    }

    #[test]
    fn test_roundtrip_one_packet() {
        let (mut tx, mut rx) = get_transport_peers();

        let some_packet = write_packet(&mut tx, fake_packet())
            .expect("did not get a fake packet");

        let mut engine: PacketEngine<EventReq> = PacketEngine::new();
        let sz = engine.drain_read(&some_packet[..]).expect("could not read");
        assert_eq!(sz, some_packet.len());

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(1, p);

        let p = engine.drain_queue().pop_front().expect("no packet");

        match p.msg {
            EventReq::Ping { msg } => assert!(msg.contains("test")),
            _ => panic!("invalid test message"),
        }
    }

    #[test]
    fn test_partial_full_header() {
        let (mut tx, mut rx) = get_transport_peers();

        let some_packet = write_packet(&mut tx, fake_packet())
            .expect("did not get a fake packet");

        let mut engine: PacketEngine<EventReq> = PacketEngine::new();
        let sz = engine.drain_read(&some_packet[..LEN_HEADER]).expect("could not read");
        assert_eq!(sz, LEN_HEADER);

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(0, p);

        let sz = engine.drain_read(&some_packet[LEN_HEADER..]).expect("could not read");
        assert_eq!(sz, some_packet.len() - LEN_HEADER);

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(1, p);

        let p = engine.drain_queue().pop_front().expect("no packet");

        match p.msg {
            EventReq::Ping { msg } => assert!(msg.contains("test")),
            _ => panic!("invalid test message"),
        }
    }

    #[test]
    fn test_partial_partial_header() {
        let (mut tx, mut rx) = get_transport_peers();

        let some_packet = write_packet(&mut tx, fake_packet())
            .expect("did not get a fake packet");

        let mut engine: PacketEngine<EventReq> = PacketEngine::new();
        let sz = engine.drain_read(&some_packet[..30]).expect("could not read");
        assert_eq!(sz, 30);

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(0, p);

        let sz = engine.drain_read(&some_packet[30..]).expect("could not read");
        assert_eq!(sz, some_packet.len() - 30);

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(1, p);

        let p = engine.drain_queue().pop_front().expect("no packet");

        match p.msg {
            EventReq::Ping { msg } => assert!(msg.contains("test")),
            _ => panic!("invalid test message"),
        }
    }

    #[test]
    fn test_full_then_partial_trailer() {
        let (mut tx, mut rx) = get_transport_peers();

        let packet_a = write_packet(&mut tx, fake_packet())
            .expect("did not get a fake packet");

        let packet_b = write_packet(&mut tx, fake_packet())
            .expect("did not get a fake packet");

        let mut engine: PacketEngine<EventReq> = PacketEngine::new();
        let sz = engine.drain_read(&packet_a[..]).expect("could not read");
        assert_eq!(sz, packet_a.len());

        let partial_sz = LEN_HEADER + 1;
        let sz = engine.drain_read(&packet_b[..partial_sz]).expect("could not read");
        assert_eq!(sz, partial_sz);

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(1, p);

        let sz = engine.drain_read(&packet_b[partial_sz..]).expect("could not read");
        assert_eq!(sz, packet_b.len() - partial_sz);

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(1, p);

        assert!(engine.drain_queue().pop_front().is_some());
        assert!(engine.drain_queue().pop_front().is_some());
        assert!(engine.drain_queue().pop_front().is_none());
    }

    #[test]
    fn test_full_then_full() {
        let (mut tx, mut rx) = get_transport_peers();

        let packet_a = write_packet(&mut tx, fake_packet())
            .expect("did not get a fake packet");

        let packet_b = write_packet(&mut tx, fake_packet())
            .expect("did not get a fake packet");

        let mut engine: PacketEngine<EventReq> = PacketEngine::new();
        let sz = engine.drain_read(&packet_a[..]).expect("could not read");
        assert_eq!(sz, packet_a.len());

        let sz = engine.drain_read(&packet_b[..]).expect("could not read");
        assert_eq!(sz, packet_b.len());

        let p = engine.try_parse(&mut rx).expect("could not parse");
        assert_eq!(2, p);

        assert!(engine.drain_queue().pop_front().is_some());
        assert!(engine.drain_queue().pop_front().is_some());
        assert!(engine.drain_queue().pop_front().is_none());
    }
}
