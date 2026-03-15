# project `remembrance`

## ⚠️ Disclaimer

This project is under active development and is considered alpha-quality
software. It is not feature complete and may have serious bugs. Please do not
use this software on a production system without careful review of the
accompanying documentation & code.

## Overview

This is a complete backup & replication system for users of ZFS who wish
to do some or all of the following:

- automatically create snapshots at specified intervals
- thin those snapshots based on a configurable pruning policy
- replicate the snapshots to another host or zpool

You do not need to buy into all the functionality at once. For example you can
do just replication without automatic snapshotting or pruning. If you're plush
with disk space you could also perform automatic snapshotting by itself, with
no pruning policy, though that's probably not advisable.

## Architecture

The basic architecture is split into two an Elixir web server, `snapcon`, and a
Rust daemon `cyrene` which runs on a host and exposes `zfs` and `zpool`
commands on that host via an authenticated RPC system. Both the controller and
hosts will need an `ed25519` keypair generated which is used for authenticating
all commands exchanged between the two nodes.

The `snapcon` acts as the master controller of your backup system. It provides
centralized configuration and monitoring for all the hosts and zpools connected
to the controller. No configuration on an individual host is needed other than:
(a) giving it the URL of a controller and a unique hostname, (b) configuring a
private key for the host, along with the public key of your controller. All
other configuration of an individual host is managed on the controller and
applied automatically to a host when it connects & authenticates.

The `cyrene` daemon effectively exists to actually enact the ZFS changes on
that host, as such it must be running as either `root` or an account that has
been delegated sufficient ZFS permissions for what you are trying to do. The
daemon will need at least one network interface and listener port, though for
concurrency it is recommended you alot multiple listener ports. (The maximum
number of ZFS replication sub-processes is ultimately bounded by the available
listener ports.)

`snapcon` exposes both an HTTP API endpoint, along with a WebSocket endpoint
for bidirectional communication with the hosts. Most of the status and
configuration messages are done over plain HTTP, whereas daemon control
messages are delivered over the long-lived WebSocket.

### Cautions

Currently all traffic is delivered over plain HTTP/WS, though the traffic is
authenticated by host at a sub-protocol level. **Traffic sent in the clear
includes metadata about your ZFS pool & datasets, along with the replication
traffic itself.**

While `snapcon` and it's control traffic can be put behind a reverse proxy
doing TLS termination there is currently no option to configure using TLS for
the replication traffic itself.

As such it is **strongly suggested** that you limit `snapcon` traffic to an
isolated subnet; ideally a private network protected by a VPN like `wireguard`
which encrypts the traffic between the hosts.

Another caution is of course that this tool is running administrative ZFS
commands on your behalf which will, in an automated fashion, **irreversibly
destroy your data as configured.** - It is crucial that you read and understand
all configuration instructions before attempting to use this tool; and where
possible you should take advantage of dryrun or similar debugging options to
test your policies before enacting them.

### Replication

- *TODO: replication snapshot naming scheme*

Like `syncoid` we expect to be able to manage snapshots on your pool that are
used solely for replication. You should not remove these snapshots during
normal operation as doing so would potentially break the incremental
replication chain.

In the event one of its replication snapshots is removed the `snapcon` will
attempt to find the newest-common-snapshot and perform re-replication from
that point forward, but if the controller and host drift out of sync this
may not be possible without manual intervention.

Replication is performed using the `-I` flag, and recursive replication is
always done using the ZFS `-r` flag where possible. We currently do not provide
options to filter snapshots or datasets in a way that would conflict with ZFS'
ability to manage recursion itself. It is suggested that you organize your
datasets such that their layout mirrors your backup & retention policies.

We explicitly avoid starting & creating many small send streams as we find it
drastically slows down replication by repeatedly doing redundant metadata walks
along with the penalties associated with connection teardown/setup.

If your backup policy is "swiss cheese", and you want to be able to have
complete control over what datasets and snapshots are being replicated, this is
probably not the tool for you. Instead we always replicate all available
snapshots; the sender and receiver are individually responsible for pruning
those datasets according to your retention policies.

### Snapshotting

All snapshotting is performed on a fixed interval. (Though you can have
overlapping snapshot policies on a dataset, operating at differing intervals,
so long as your configured naming scheme would not cause a name collision.)

Pruning is performed with a matchspec that has the following grammar, it is
substantially similar to the `zrepl` "grid" specification:

- Where `i` is an interval: <n><interval>
  - `s[econds]
  - `m[inutes]`
  - `h[ours]`
  - `d[ays]`
  - `w[eeks]`
  - `y[ears]`

- NOTE: that a year is defined as 52 weeks, and a week is defined as 7 days.

- A bucket is defined with the syntax `[n]x[i](keep=<all|n>) | ...`
- Buckets are chained together with the `|` pipe character.

Each segment defines one or more buckets, the `[n]x` is a repetition operator
and must be a positive integer. The `[i]` interval must start with a positive
integer and end with one of the intervals specified above.

The `(keep=)` segment is optional, it is always implied and it defaults to
`keep=1` if not specified explicitly.

The matchspec creates a number of buckets according to your specified intervals
and then iterates over the dataset's snapshots in chronological order to sort
them into those buckets. (Where chronological order is defined as the exact
`creation` property.)

A bucket will consume snapshots until either:

- a snapshot falls outside it's time interval, at which point processing of
  the next bucket will begin ...

- or the bucket reaches the upper limit of its `keep=` count.

Processing will continue like this until all the bucket's constraints have been
satisfied. (Note that some buckets may end up with zero snapshots if you have
none over that time-interval. This may happen if you're pruning a
manually-snapshotted dataset, you have recently changed your pruning or
snapshotting policy, or just simply because your snapshot interval and pruning
intervals don't align.)

Any snapshots that "fall off the end", i.e. snapshots left over that did not
get marked by any bucket, will be destroyed.

**One critical difference between `snapcon` and `zrepl` is that we do not
destroy arbitrary snapshots. Based on your configuraiton certain snapshots are
considered to be 'owned' or 'managed' by the `snapcon` process.**

Your snapshot and pruning policy will have a prefix which consists of a host
identifier along with some (optional) user-configured prefix. These prefixes
are used as part of automatic snapshot creation, and then used again to filter
the list of snapshots which are being considered for destruction.

Snapshots which do not explicitly match the prefix configured in the pruning
policy will be left alone unless some other policy is configured to manage
them. (Again: you can have multiple such policies so long as their names do not
conflict with one another.)




