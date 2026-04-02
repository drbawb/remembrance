use serde::{Deserialize, Serialize};

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize)]
pub struct Packet<T> {
    pub nonce: CorrelationId,
    pub ttl: u64,
    pub len: Option<usize>,
    pub msg: T,
}

// impl<T: fmt::Debug> fmt::Debug for Packet<T> {
//     fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
//         write!(f, "ttl {}", self.ttl)?;
// 
//         match self.len {
//             Some(len) => write!(f, " len {len}")?,
//             None => write!(f, " len ?")?,
//         };
// 
//         write!(f, " nonce {:16x}\n", self.nonce.0)?;
//         write!(f, "{:?}", self.msg)?;
// 
//         Ok(())
//     }
// }

impl Packet<()> {
    // TODO: wow I hate this, T=() lmao ...
    // This is here so that this freestanding function can be called
    // even if you don't have an instantiation of a packet ...
    pub fn calc_ttl(seconds: u64) -> u64 {
        let wall_t = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time moving backwards? that's bad ...")
            .as_secs();

        wall_t + seconds
    }
}

impl<T> Packet<T> {
    pub fn from_parts(nonce: u128, ttl: u64, msg: T) -> Self {
        let nonce = CorrelationId(nonce);
        Packet { nonce, ttl, msg, len: None }
    }
}

#[derive(Debug, Deserialize, Serialize)]
pub enum EventReq {
    Ident { version: u16 },
    Ping { msg: String }, 
    ZfsListDataset(ZfsListArgs),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum EventRep {
    Ident { version: u16, name: String },
    ZfsList { list: Vec<String> },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ZfsListArgs {
    pub name:      Option<String>,
    pub depth:     Option<u16>,
    pub ent_ty:    ZfsListType,
    pub recursive: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ZfsListType {
    Filesystem,
    Snapshot,
    Volume,
    Bookmark,
    All,
}

#[derive(Copy, Clone, Debug, Deserialize, Serialize)]
pub struct CorrelationId(pub u128);


pub fn build_packet(msg: EventRep) -> Packet<EventRep> {
    let nonce = CorrelationId(rand::random());

    let wall_t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moving backwards? that's bad ...")
        .as_secs();

    let ttl = wall_t + 30;

    Packet { nonce, msg, ttl, len: None }
}
