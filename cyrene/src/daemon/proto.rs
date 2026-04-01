use data_encoding::BASE64;
use ed25519_dalek::{Signature, VerifyingKey, Verifier};
use ed25519_dalek::{SigningKey, Signer};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::config::{self, DaemonConfig};
use super::err::*;
use super::{EventReq, EventRep, Packet};

use std::fmt::Debug;
use std::io::{self, Cursor, Read, Write};
use std::marker::PhantomData;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

// TODO: wow I hate this, lmao ...
trait PacketTraits: Debug + Serialize {}
impl PacketTraits for EventReq {}
impl PacketTraits for EventRep {}

#[derive(Debug)]
pub struct Codec<'a> {
    pub cfg: &'a DaemonConfig,
    
    // pub _p_in:  PhantomData<Req>,
    // pub _p_out: PhantomData<Rep>,
}

impl<'a> Codec<'a> {
    // TODO: want this to return a packet (maybe?)
    #[tracing::instrument]
    pub fn decode_packet(&self, buf: &[u8]) -> Result<(u128, u64, String)> {
        use byteorder::{NetworkEndian as NE, ReadBytesExt, WriteBytesExt};

        // TODO: cache base 64 decode result
        let key_material = BASE64.decode(&self.cfg.controller.pubkey.as_bytes())
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

        Ok((nonce, ttl, output))
    }

    #[tracing::instrument]
    pub fn encode_packet(&self, pkt: Packet<EventRep>) -> Result<Vec<u8>> {
        use byteorder::{NetworkEndian as NE, WriteBytesExt};
        
        let Packet { nonce, ttl, msg, len: _ } = pkt;
        let msg = serde_json::to_string(&msg)?;
        assert!(msg.len() <= u16::MAX as usize);

        // TODO: cache base 64 decode result
        let key_material = BASE64.decode(self.cfg.controller.privkey.as_bytes())
            .expect("failed to decode ed25519 private key");

        let sk_bytes: &[u8; 32] = key_material.as_slice().try_into()
            .expect(&format!("invalid key length (have: {}, want: 32)", key_material.len()));

        let sk = SigningKey::from_bytes(sk_bytes);

        let mut rdr = Cursor::new(msg.as_bytes());
        let mut total = msg.len() as i32;
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

        // update the payload digest & reset our reader
        let pl_digest = hasher.finalize();
        rdr.set_position(0);

        // create signature
        let mut sig_buf = Cursor::new(Vec::with_capacity(56));

        sig_buf.write_u128::<NE>(nonce.0)?;
        sig_buf.write_u64::<NE>(ttl)?;
        sig_buf.write(&pl_digest[..])?;

        // sign with our private key
        let sig_bytes = sig_buf.into_inner();
        assert_eq!(sig_bytes.len(), 56);
        let sig = sk.sign(&sig_bytes);

        // assemble final packet
        let mut packet = Cursor::new(vec![]);
        packet.write_u128::<NE>(nonce.0)?;
        packet.write_u64::<NE>(ttl)?;
        packet.write_u16::<NE>(64)?;
        packet.write_u16::<NE>(msg.len() as u16)?;
        packet.write_u16::<NE>(0x0000)?; // rsvd 1
        packet.write_u16::<NE>(0x0000)?; // rsvd 2
        packet.write_all(sig.r_bytes())?;
        packet.write_all(sig.s_bytes())?;
        packet.write_all(msg.as_bytes())?;

        Ok(packet.into_inner())
    }
}
