use blinkedblist::List as Blist;
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde::{de::SeqAccess, de::Visitor, ser::SerializeSeq};

/// A single dataset row from `zfs list -pHo name,avail,used,usedsnap`.
/// `name` is a zero-copy slice into the original stdout `Bytes`.
/// `parent` is the slot index of the parent dataset in the owning
/// `ZfsDatasetList`, or `None` for pool-level (root) entries.
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ZfsDataset {
    #[serde(serialize_with = "bytes_as_str", deserialize_with = "str_as_bytes")]
    pub name:     Bytes,
    pub avail:    u64,
    pub used:     u64,
    pub usedsnap: u64,
    pub parent:   Option<u32>,
}

/// Flat list of all datasets parsed from a single `zfs list` invocation.
/// Parent-child relationships are encoded via `ZfsDataset::parent` indices.
/// Implements `Serialize` as a JSON array.
///
pub struct ZfsDatasetList(pub Blist<ZfsDataset>);

/// Tree-shaped representation of a dataset hierarchy.
/// Each node owns its children. Natural for recursive destructuring
/// on the receiving end (e.g. Elixir pattern matching).
///
#[derive(Debug, Serialize, Deserialize)]
pub struct ZfsTreeNode {
    #[serde(serialize_with = "bytes_as_str", deserialize_with = "str_as_bytes")]
    pub name:     Bytes,
    pub avail:    u64,
    pub used:     u64,
    pub usedsnap: u64,
    pub children: Vec<ZfsTreeNode>,
}

impl ZfsDatasetList {
    /// Build a nested tree from the flat list. Roots (parent=None) become
    /// top-level entries. Uses the parent slot indices to reconstruct hierarchy.
    pub fn to_tree(&self) -> Vec<ZfsTreeNode> {
        let entries: Vec<&ZfsDataset> = self.0.iter().collect();
        let n = entries.len();

        // each slot accumulates its children; walk reverse so leaves are ready first
        let mut buckets: Vec<Vec<ZfsTreeNode>> = (0..n).map(|_| Vec::new()).collect();
        let mut roots: Vec<ZfsTreeNode> = Vec::new();

        for i in (0..n).rev() {
            let e = entries[i];
            let mut kids = std::mem::take(&mut buckets[i]);
            kids.reverse(); // children were pushed in reverse order

            let node = ZfsTreeNode {
                name:     e.name.clone(),
                avail:    e.avail,
                used:     e.used,
                usedsnap: e.usedsnap,
                children: kids,
            };

            match e.parent {
                Some(p) => buckets[p as usize].push(node),
                None    => roots.push(node),
            }
        }

        roots.reverse();
        roots
    }
}

/// Parse `zfs list -pHo name,avail,used,usedsnap` stdout into a flat list.
/// `buf` is the frozen stdout `Bytes`; `name` fields are zero-copy slices.
/// Parent-child relationships are encoded as slot indices into the returned list.
///
pub fn parse_zfs_list(buf: Bytes) -> ZfsDatasetList {
    // stack entries: (depth, slot_index)
    let mut stack: Vec<(usize, u32)> = Vec::new();
    let mut list: Blist<ZfsDataset> = Blist::new();
    let mut slot: u32 = 0;

    for line in buf.split(|&b| b == b'\n') {
        let line = if line.last() == Some(&b'\r') { &line[..line.len()-1] } else { line };
        if line.is_empty() { continue; }

        let mut fields = line.splitn(4, |&b| b == b'\t');
        let Some(name_raw) = fields.next() else { continue };
        let avail    = parse_u64(fields.next().unwrap_or(b""));
        let used     = parse_u64(fields.next().unwrap_or(b""));
        let usedsnap = parse_u64(fields.next().unwrap_or(b""));

        let depth  = depth_of(name_raw);
        let name   = buf.slice_ref(name_raw);

        // pop stack until top is a strict ancestor (depth < ours)
        while stack.last().map_or(false, |&(d, _)| d >= depth) {
            stack.pop();
        }

        let parent = stack.last().map(|&(_, idx)| idx);
        list.push_back(ZfsDataset { name, avail, used, usedsnap, parent });

        stack.push((depth, slot));
        slot += 1;
    }

    ZfsDatasetList(list)
}

impl Serialize for ZfsDatasetList {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(None)?;
        for entry in self.0.iter() {
            seq.serialize_element(entry)?;
        }
        seq.end()
    }
}

impl<'de> Deserialize<'de> for ZfsDatasetList {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct ListVisitor;

        impl<'de> Visitor<'de> for ListVisitor {
            type Value = ZfsDatasetList;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a sequence of ZfsDataset entries")
            }

            fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Self::Value, A::Error> {
                let mut list: Blist<ZfsDataset> = Blist::new();
                while let Some(entry) = seq.next_element::<ZfsDataset>()? {
                    list.push_back(entry);
                }
                Ok(ZfsDatasetList(list))
            }
        }

        d.deserialize_seq(ListVisitor)
    }
}

impl std::fmt::Debug for ZfsDatasetList {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ZfsDatasetList({:?})", self.0)
    }
}

pub fn debug_print(list: &ZfsDatasetList) {
    use crate::daemon::units::Size;

    for (slot, node) in list.0.iter().enumerate() {
        let depth  = node.name.iter().filter(|&&b| b == b'/').count();
        let indent = "  ".repeat(depth);
        let name   = std::str::from_utf8(&node.name).unwrap_or("?");

        let stat = (
            Size::from_u64(node.avail),
            Size::from_u64(node.used),
            Size::from_u64(node.usedsnap));

        tracing::info!(
            parent = node.parent, 
            "{}{} [{}] avail={} used={} snap={}",
            indent, name, slot, stat.0, stat.1, stat.2);
    }
}

fn bytes_as_str<S: Serializer>(b: &Bytes, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(std::str::from_utf8(b).unwrap_or(""))
}

fn str_as_bytes<'de, D: Deserializer<'de>>(d: D) -> Result<Bytes, D::Error> {
    let s = <&str>::deserialize(d)?;
    Ok(Bytes::copy_from_slice(s.as_bytes()))
}

fn depth_of(name: &[u8]) -> usize {
    name.iter().filter(|&&b| b == b'/').count()
}

fn parse_u64(field: &[u8]) -> u64 {
    std::str::from_utf8(field)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn collect(list: &ZfsDatasetList) -> Vec<&ZfsDataset> {
        list.0.iter().collect()
    }

    #[test]
    fn test_basic_tree() {
        let input = b"tank\t100\t50\t10\ntank/data\t80\t40\t5\ntank/data/sub\t70\t30\t2\n";
        let result = parse_zfs_list(Bytes::from_static(input));
        let nodes = collect(&result);

        assert_eq!(nodes.len(), 3);
        assert_eq!(&nodes[0].name[..], b"tank");
        assert_eq!(nodes[0].parent, None);
        assert_eq!(nodes[0].avail, 100);

        assert_eq!(&nodes[1].name[..], b"tank/data");
        assert_eq!(nodes[1].parent, Some(0));

        assert_eq!(&nodes[2].name[..], b"tank/data/sub");
        assert_eq!(nodes[2].parent, Some(1));
        assert_eq!(nodes[2].usedsnap, 2);

        println!("basic: {result:?}");
    }

    #[test]
    fn test_multiple_pools() {
        let input = b"rpool\t200\t100\t0\ntank\t100\t50\t10\ntank/data\t80\t40\t5\n";
        let result = parse_zfs_list(Bytes::from_static(input));
        let nodes = collect(&result);

        assert_eq!(nodes.len(), 3);
        assert_eq!(&nodes[0].name[..], b"rpool");
        assert_eq!(nodes[0].parent, None);

        assert_eq!(&nodes[1].name[..], b"tank");
        assert_eq!(nodes[1].parent, None);

        assert_eq!(&nodes[2].name[..], b"tank/data");
        assert_eq!(nodes[2].parent, Some(1));

        println!("multi: {result:?}");
    }

    #[test]
    fn test_serialize_flat() {
        let input = b"tank\t100\t50\t10\ntank/data\t80\t40\t5\n";
        let result = parse_zfs_list(Bytes::from_static(input));
        let json = serde_json::to_string(&result).expect("serialize failed");
        // flat array, not nested
        assert!(json.starts_with('['));
        assert!(json.contains("\"parent\":null"));
        assert!(json.contains("\"parent\":0"));

        println!("json: {json:?}");
    }

    #[test]
    fn test_to_tree_basic() {
        let input = b"tank\t100\t50\t10\ntank/data\t80\t40\t5\ntank/data/sub\t70\t30\t2\n";
        let list = parse_zfs_list(Bytes::from_static(input));
        let tree = list.to_tree();

        assert_eq!(tree.len(), 1); // one root
        assert_eq!(&tree[0].name[..], b"tank");
        assert_eq!(tree[0].children.len(), 1);
        assert_eq!(&tree[0].children[0].name[..], b"tank/data");
        assert_eq!(tree[0].children[0].children.len(), 1);
        assert_eq!(&tree[0].children[0].children[0].name[..], b"tank/data/sub");
        assert!(tree[0].children[0].children[0].children.is_empty());
    }

    #[test]
    fn test_to_tree_multi_pool() {
        let input = b"rpool\t200\t100\t0\ntank\t100\t50\t10\ntank/data\t80\t40\t5\n";
        let list = parse_zfs_list(Bytes::from_static(input));
        let tree = list.to_tree();

        assert_eq!(tree.len(), 2); // two roots
        assert_eq!(&tree[0].name[..], b"rpool");
        assert!(tree[0].children.is_empty());
        assert_eq!(&tree[1].name[..], b"tank");
        assert_eq!(tree[1].children.len(), 1);
    }

    #[test]
    fn test_tree_roundtrip_json() {
        let input = b"tank\t100\t50\t10\ntank/data\t80\t40\t5\n";
        let list = parse_zfs_list(Bytes::from_static(input));
        let tree = list.to_tree();

        let json = serde_json::to_string(&tree).expect("serialize tree");
        let back: Vec<ZfsTreeNode> = serde_json::from_str(&json).expect("deserialize tree");

        assert_eq!(back.len(), 1);
        assert_eq!(&back[0].name[..], b"tank");
        assert_eq!(back[0].avail, 100);
        assert_eq!(back[0].children.len(), 1);
        assert_eq!(&back[0].children[0].name[..], b"tank/data");

        println!("tree json: {json}");
    }
}
