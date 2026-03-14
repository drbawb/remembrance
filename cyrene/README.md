This is a daemon which serves two primary purposes:

1. Firstly it listens for RPC messages from trusted parties and responds to
   them in kind. It essentially acts as an intermediary between the controller
   and subordinates, greatly limiting the command-set which the controller has
   access to.

2. Secondly it handles invoking `zfs-send`/`zfs-receive` and routing them onto
   a TCP pipe for transport between two agents. It monitors the traffic over
   the pipe and broadcasts status messages on the control port.





- commands
  - list_filesystems
    - stem: string
    - recursive: bool
    - type: string ;; (snapshot | filesystem | volume | all)

  - read_properties
    - stem: string
    - property: [string]
    - recursive: bool
    - type: string ;; (snapshot | filesystem | volume | bookmark | all)



