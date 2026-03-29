# Wire Format

Currently we support one transport, [WebSocket][ws-rfc], used as a reliable,
bidirectional communication channel between the daemons & controller. The peers
exchange binary frames with each other using the protocol described in this
document. Multi-byte primitives are sent over the wire in big endian order
unless otherwise specified.

The following primitives exist:

```
u8  : 8-bit  be word
u16 : 16-bit be word
u32 : 32-bit be word
u64 : 64-bit be word

[u8]       : byte array
[u8;n]     : byte array of known (dependent) length
[string;n] : [u8;n] interpreted as utf-8 string
[ascii;n]  : [u8;n] interpreted as ascii string
```

## WebSocket Transport

The transport should be kept-alive by the `controller` periodically sending
`ping` control frames, and the `daemon` responding automatically with a `pong`
control frame. These control frames are unauthenticated and outside the scope
of the packet encoding described below. (The following packet authentication
scheme will only be applied to `binary` frames.)

Each binary frame should contain a payload of the following opaque format:

```
header:
nonce    : [u8; 16] ;; 128-bit unsigned integer
expiry   : u64      ;; 64-bit unix timestamp (seconds from epoch)
sig_len  : u16      ;; signature length, always =64
pay_len  : u16      ;; payload length, should be <= (64 * 1024)
reserved : u16      ;; reserved word for future flags
reserved : u16      ;; reserved word for future flags

payload:
[u8; sig_len] : buf_sig
[u8; pay_len] : buf_payload
[u8; ...]     : any contents after `pay_len` is ignored and unauthenticated
```

The packet header totals `32 bytes` on the wire and it should be read in its
entirety before processing the payload below. The payload should be considered
as untrusted until the procedure described below has been completed and is
free from error.

The `sig_len` field allows for a variable sized signature, a capability
reserved for future expansion. `sig_len` is typically 64-bytes and `buf_sig` 
should be interpreted as a signature produced with an `ed25519` signing key.
(This field may be reinterpreted or ignored if any of the `reserved` words are
set and the sender/receiver use them to negotiate selection of some other
signature.)

This key is shared using some identity mechanism out-of-band. In the WebSocket
transport this is accomplished by setting the `x-cyrene-id` header on the
initial HTTP request which will be upgraded by this transport.

Two 16-bit words are reserved for future expansion. A conforming parser must
check these flags. All parsers must support this base format (0x0000; 0x0000).

_A/N: TODO ;; error message format_
Parsers should return a non-fatal error, `PLACEHOLDER: ERR_CMD_NOT_UNDERSTOOD` 
if they encounter a sequence of reserved words they are not equipped to decode.
The reserved words are an opaque bitfield and must be interpreted according to
the version specified in the `PLACEHOLDER: APP_NEGOTIATE_VER` message.

Messages during the initial handshake *MUST* be sent without reserved flags
until a version negotiation packet (or packet sequence) passes authentication
and deserialization.

### Early Verification

_The first packet must be an ed25519-signed `Ident` message. The message will
be sent from the controller to the daemon which is connecting. The daemon will
send an identificaiton response including the configured hostname; if the
identity matches what is configured for the key then both peers will transition
to a fully authenticated state._

_If the first packet is anything other than an `Ident` message the reserved
flags must be set to signal negotiation, and the sender/receiver must negotiate
some other authentication mechanism accordingly before sending the `Ident`
message._

A frame will undergo `validity` considerations as follows:

- A conforming receiver will first verify the packet has not expired by reading
  the expiry date and verifying it against the wall clock.

- If the message is not expired the nonce will be checked against a list of
  previously received nonces. (This list will not contain nonces known to have
  expired.)

A packet failing to meet these `validity` criteria will result in the following:

- A previously unauthenticated connection will be closed. The receiver is not
  obligated to respond to the sender, but can do so out-of-band via setting
  a reason on the Close frame indicating that authentication was not successful.

- If the connection was previously established as authentic the message will be
  dropped and the receiver may log a replay attempt locally. The receiver is not
  obligated to inform the sender that the message was replayed/dropped.

  - A receiver may instead elect to close the connection in response to a
    replayed message. If doing so, on a previously authenticated connection,
    it must send the appropriate disconnection signal.

### Late Verification

A `valid` frame will then undergo these `authenticitiy` considerations:

- The receiver will read `buf_sig` into memory for later comparison

- The receiver will create its own parallel signature (`ver_sig`) using:
  - `verify_ed25519(buf_sig, {nonce, expiry, payload})`

- The receiver will compare `buf_sig` to `ver_sig`, and:

  - On success: the payload will be deserialized accordingly and forwarded to
    the application domain.

  - On failure: the connection will be closed. As per the `validity` section a
    receiver is not obligated to respond to the sender, but can do so out-of-band
    via setting a reason on the Close frame indicating authentication was not
    successful.

The peer's signature (`buf_sig`) will be read if the message is both `valid`
and `authentic`. The receiver will compute its own digest using the `nonce`,
`ttl`, and `buf_payload` bytes in big endian order. (It is recommended at this
stage that the receiver read the payload in fixed-sized blocks to prevent
malicious senders from allocating arbitrary-sized buffers.)

The peer's public `ed25519` verifying key will be used to compare the computed
signature to the signature they sent in `buf_sig` - assuming the verification
passes the receiver is free to allocate & interpret `buf_payload` as an
application-level message.

### Message Parsing

When the reserved flag fields are set to `0x0` then `buf_payload` is expected
to be a UTF-8 encoded JSON string. (Future flags may alter the expectation of
how a conforming parser should interpret the payload; as such the `buf_payload`
field is considered to be an opaque byte-array from the perspective of the
wire format decoder.)

# Application Message Format

The application message format is canonically owned by the Rust implementation
of the `cyrene` daemon. This implementation expects messages to be exchanged
via UTF-8 encoded JSON strings. (Limited portions of the protocol may be
restricted to ASCII.)

The canonical format is esentially "whatever `serde_json` does with the type."

There are two broad categories of messages:

- `EventReq`: the daemon's inbound event queue from the controller
- `EventRep`: the daemon's outgoing submission queue

## Task Lifecycle

Events generally consist of a command, some arguments, and optionally a
correlation ID.

Tasks which can complete quickly (under several hundred milliseconds)
often lack a correlation ID and block the event loop until they
both complete *and* generate a reply to the controller.

Other tasks, which are expected to take some time to complete, will instead
generate and return a correlation ID to the peer. This ID will be tracked
by the owner with some continuation-state. The continuation, either when it
is fired or times out, will optionally send an asynchronous reply containing
the correlation ID.

### Long-running Tasks

The peer upon receiving a message with a correlation ID will check a local
cache of pending submissions it was waiting for, and use the correlation ID
to update the appropriate application state.

**Tasks which return a correlation ID are generally fallible**, meaning, such
tasks may be dropped under heavy load, may fail non-fatally, or may not
generate output for many minutes or hours. When possible the application should
include an expected response time with its correlation ID; however the
expiration of this timestamp does NOT strictly imply that the task failed.

If a correlation entry is determined to be stale by its associated `ttl` the
application should use an appropriate status API which takes the correlation
ID as input and returns task information as its output. This status API may
be used to refresh the cache's `ttl` value where applicable.


### The Command Buffer

A transport should allocate a fixed-sized buffer for storing pending 
correlation state. In the event this buffer is exhaused a transport
will issue a `PLACEHOLDER: CMD_NOT_READY` response. The sender should
buffer or perform neccessary accounting on its side to reschedule the
task, and retry the task at a later time.

The receiving thread should generally not block when its buffer is exhausted.
It is expected that it remain able to respond to commands which do not require
asynchrony or other allocations of fixed resources.

_A/N: TODO ;; properly specify what a "continuation" looks like_

### Continuations

When a command is scheduled to run in the background (or to be run after an
interval elapses) that completion must be bound to an identity known as a
"correlation ID." This mapping must ultimately be a function which:

a. generates a response on a background thread, handling failure of the thread
   as appropriate, and generally translating the result of that computation
   into an application level message.

b. submits the response to the transport for encoding & transmission via
   a clone of the submission queue. used nonces must be added to the daemon's
   packet authenticity cache.

c. locks and updates the daemon's state such that the handled correlation ID
   is removed from the list of pending submissions.


[ws-rfc]: https://datatracker.ietf.org/doc/html/rfc6455


