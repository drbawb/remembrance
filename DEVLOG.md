##  development log

### 2026-04-05

Major architectural change:

1. `snapcon` and `cyrene` swap to being the responder and initiator respectively.
2. The Noise handshake changed from `KK` to `IK`.
3. `snapcon` now learns the daemon's public key on connection acceptance and
   uses that to look up identity information in the `%Host{}` table.
4. `cyrene` now parses the ZFS dataset listing into a tree-structure internally.

Protocol changes: 

- `cyrene` now exposes both a flat listing of ZFS datasets (where the parent is
  stored as a back-pointer by array index) along with a nested tree listing of
  datasets.

- `snapcon` now has an embedded schema to aid in parsing/validating the 
  responses from `cyrene`, as well as to make working w/ them on the frontend
  more user friendly.

Internal changes:

- The `HandshakeEngine` is re-done to support being in the initiator role.

- Using the `bytes` crate to support cheap clones/subslices into the
  buffer we allocate for the respone from `zfs-list`.

- Using the `blinkedblist` crate to maintain the ZFS listing table in a way
  that is friendly both to quick forward scans of all children, as well as
  navigating the hierarchy.

  - Primary motivation for adding this support is that it will be useful
    for applying the configuration "inheritance" scheme later when we need
    to apply things like snapshot/pruning rules either by depth or to
    arbitrary nodes and their children.

