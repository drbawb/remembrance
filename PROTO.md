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

`sig_len` is typically 64-bytes and `buf_sig` is a signature produced with an
ed25519 signing key. (This key is shared using some identity mechanism out of
band. In the WebSocket transport this is done by setting the `x-cyrene-id`
header on the initial HTTP request which will be upgraded by this transport.)

### Early Verification

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

[ws-rfc]: https://datatracker.ietf.org/doc/html/rfc6455


