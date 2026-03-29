use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum EventReq {
    Ident { version: u16 },
    Ping { msg: String }, 
    ZfsListDataset(ZfsListArgs),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum EventRep {
    Ident { version: u16, name: String },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ZfsListArgs {
    name:      String,
    depth:     u16,
    ent_ty:    ZfsListType,
    recursive: bool,
}

#[derive(Debug, Deserialize, Serialize)]
pub enum ZfsListType {
    Filesystem,
    Snapshot,
    Volume,
    Bookmark,
    All,
}

#[allow(dead_code)]
#[derive(Debug)]
pub struct CorrelationId(i64);
