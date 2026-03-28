use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub enum EventReq {
    Ping { msg: String }, 
    ZfsListDataset(ZfsListArgs),
}

#[derive(Debug, Deserialize, Serialize)]
pub enum EventRep {
    Test,
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

#[derive(Debug)]
pub struct CorrelationId(i64);
