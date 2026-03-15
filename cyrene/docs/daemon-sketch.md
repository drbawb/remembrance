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

