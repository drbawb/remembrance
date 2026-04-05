use serde::{Deserialize, Serialize};

use super::zfs::{ZfsDatasetList, ZfsTreeNode};

use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Deserialize, Serialize)]
pub struct Packet<T> {
    pub nonce: CorrelationId,
    pub ttl: u64,
    pub len: Option<usize>,
    pub msg: T,
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
    /// The response to an `Ident` request includes the daemon's
    /// preferred protocol version, along with its configured host name.
    ///
    /// - The version should either match what was in the `Ident` request,
    ///   OR the controller/daemon must do additional negotiation to ensure
    ///   the selected version is compatible.
    ///
    /// - The name sent MUST match what the controller has on-file for the
    ///   configured encryption key, or the controller will abort the connection.
    ///  
    Ident { version: u16, name: String },

    /// A flat listing of all datasets. (It is important that a receiver
    /// maintain consistent ordering of this list, as the parent back-pointer
    /// is encoded as an index into this list.)
    ///
    ZfsList { list: ZfsDatasetList },

    /// A list of root datasets. (There may be more than one on a system with
    /// several ZFS pools imported simultaneously.)
    ///
    ZfsTree { list: Vec<ZfsTreeNode> },
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

pub fn calc_ttl(seconds: u64) -> u64 {
    let wall_t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("time moving backwards? that's bad ...")
        .as_secs();

    wall_t + seconds
}
