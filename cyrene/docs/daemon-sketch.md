# protocol basics

- read cached config from disk
  - start the local snapshotting worker threads w/ old config

- http get `/api/config/:client`
  - set the x-cyrene auth headers
  - we should get either a failure to auth
  - a failure because the controller has no config for us
  - or success including a runtime config to apply

- if the controller knows us, start a websocket
  - connect w/ x-cyrene headers
  - send initial handshake messages
  - wait for control messages
    - most likely controller will start scheduling replication jobs

- controller will send us replication jobs
  - push them onto a FIFO queue
  - they will either be `(incoming|outgoing)`
    - e.g. we need to set up `zfs send` or `zfs receive`

  - setup the zfs subprocess with the requested flags
  - acknowledge the job with a job status message
    - something like `[:job_id, :status]`


# authentication scheme (todo)

1. client sends an authentication packet like:
   `["auth", "<nonce>", "<signature>"]

2. server stores packet in a limited ring-buffer like structure.
   sends rate limit messages or other similar error to backoff a
   rogue client that is sending too many authentication packets
   without sending the corresponding messages to drain the buffer.

3. client sends a message packet like:
  `[nonce, timestamp, {"SomeType": {"field_a": a, "field_b": b}}]`

4. server digests the received body, and parses the JSON to extract
   the authentication metadata.

5. reject the packet if the timestamp is outside the configured replay window
6. reject the packet if the nonce is stored in our replay window buffer
7. otherwise pull the signature packet from the buffer by `nonce`
8. reject the message if we do not have that nonce, otherwise authenticate
   the message using ed25519.
   
