use blinkedblist::List as Blist;
use crossbeam_channel::{bounded, Receiver, Sender};

use std::io::{Read};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::{self, DaemonConfig};
use err::*;
use msg::*;

pub mod err;
pub mod msg;

mod tcp;

#[derive(Debug)]
struct Ratchet {
    last_start: Instant,
    restart_secs: u64,
    ratchet_secs: u64,
}

impl Ratchet {
    /// Creates a 30s ratcheting timeout
    pub fn new() -> Self {
        Self {
            last_start: Instant::now(),
            restart_secs: 1,
            ratchet_secs: 1,
        }
    }

    /// The current restart timeout as a `std::time::Duration`
    pub fn wait(&self) -> Duration { Duration::from_secs(self.restart_secs) }

    /// Reset the internal clock when the supervised thread starts successfully 
    pub fn reset(&mut self, at: Instant) { self.last_start = at; }

    /// Ratchets up in `* 2` increments until reaching a 30s saturation point
    pub fn ratchet_up(&mut self) {
        self.restart_secs = u64::min(30, self.restart_secs * 2);
        self.ratchet_secs = 1; // reset the ratchet step size
    }

    /// Ratchets down in `/ 2` increments until reaching the 1s saturation point
    pub fn ratchet_down(&mut self) {
        if self.restart_secs <= 1 { return; }

        let rst_since = self.last_start.elapsed();
        let rat_since = Duration::from_secs(self.ratchet_secs);

        if rst_since > rat_since {
            let prev_rt_s = self.restart_secs;
            self.restart_secs = u64::max( 1, self.restart_secs.saturating_sub(self.ratchet_secs));
            self.ratchet_secs = u64::min(30, self.ratchet_secs * 2);
            eprintln!("backoff reduced from {}s => {}s", prev_rt_s, self.restart_secs);
        }
    }
}

pub fn run_command_queue() -> Result<String> {
    println!("booting daemon ...");

    let dmn_init = DaemonInit::new();

    let thread_evt = thread::spawn(move || {
        let mut kernel = dmn_init.kernel;

        match kernel.event_loop() {
            Err(err) => Err(RunError::Misc(format!("{err:?}"))),
            Ok(_) => { drop(kernel.pending); Ok(()) }, // TODO: use pending
        }
    });

    let tcp_init = tcp::ClientInit {
        name: "hitomi".into(), // TODO: config
        req_tx: dmn_init.tx_req_q.clone(),
        rep_tx: dmn_init.tx_rep_q.clone(),
        rep_rx: dmn_init.rx_sub_q,
    };

    let client = tcp::Client::new(tcp_init)
        .map_err(|e| RunError::Misc(format!("could not start tcp client: {e:?}")))?;

    let mut ratchet_ws = Ratchet::new();
    let mut thread_ws = thread::spawn(move || {
        tcp::client_event_loop(client)
    });

    loop { // TODO: remove websocket thread
        thread::sleep(Duration::from_millis(1000));

        if thread_ws.is_finished() {
            let ws_result = thread_ws.join()
                .inspect_err(|err| { eprintln!("w/s thread panic: {err:?}") })
                .ok().expect("ws panic exit"); // TODO: supervisor trap exit

            println!("ws exit: {ws_result:?}");
            // let rx_rep_q = ws_result
            //     .inspect_err(|err| { eprintln!("w/s fatal error: {err:?}") })
            //     .ok().expect("ws fatal exit"); // TODO: supervisor trap exit

            // apply backoff
            thread::sleep(ratchet_ws.wait());

            // TODO: tcp reinit
            // attempt to reboot w/ our reclaimed submission queue
            // let ws_init = tcp::WsInit {
            //     name: "hitomi".into(), // TODO: config
            //     req_tx: dmn_init.tx_req_q.clone(),
            //     rep_tx: dmn_init.tx_rep_q.clone(),
            //     rep_rx: rx_rep_q,
            // };

            thread_ws = thread::spawn(move || {
                thread::sleep(Duration::from_secs(30));
                todo!("restart monitor")
                // start_socket_thread(ws_init)
            });

            ratchet_ws.reset(Instant::now());
            ratchet_ws.ratchet_up();
        } else {
            ratchet_ws.ratchet_down();
        }

        if thread_evt.is_finished() {
            if let Err(msg) = thread_evt.join() {
                eprintln!("daemon exited, tearing it down: {msg:?}");
            }

            todo!("ability to restart daemon?");
        }
    }
}

pub struct DaemonKernel {
    req_q: Receiver<Packet<EventReq>>,
    sub_q: Sender<Packet<EventRep>>,

    pending: Blist<CorrelationId>,

    tx_wkr_q: Sender<Packet<EventReq>>,
    rx_wkr_q: Receiver<Packet<EventReq>>,
    tx_cfg_q: Sender<DaemonConfig>,
}

pub struct DaemonInit {
    kernel: DaemonKernel,

    tx_req_q: Sender<Packet<EventReq>>,
    tx_rep_q: Sender<Packet<EventRep>>,
    rx_cfg_q: Receiver<DaemonConfig>,
    rx_sub_q: Receiver<Packet<EventRep>>,
}

impl DaemonInit {
    pub fn new() -> DaemonInit {
        let (tx_req_q, rx_req_q) = bounded(8);
        let (tx_rep_q, rx_rep_q) = bounded(1024);
        let (tx_wkr_q, rx_wkr_q) = bounded(32);
        let (tx_cfg_q, rx_cfg_q) = bounded(8);

        let fresh_instance = DaemonKernel {
            req_q: rx_req_q,
            sub_q: tx_rep_q.clone(),
            pending: Blist::new(),

            tx_wkr_q, rx_wkr_q, tx_cfg_q,
        };


        Self {
            kernel: fresh_instance,
            tx_req_q: tx_req_q,
            tx_rep_q: tx_rep_q.clone(),
            rx_cfg_q: rx_cfg_q,
            rx_sub_q: rx_rep_q,
        }
    }
}

impl DaemonKernel {
    pub fn event_loop(&mut self) -> Result<()> {
        println!("daemon event loop running ...");
        let fr_budget_ms = Duration::from_millis(1000 / 100);

        let mut workers = vec![];
        let mut next_monitor_t = Instant::now() + Duration::from_secs(10);

        for i in 0..4 {
            let worker_rx = self.rx_wkr_q.clone();
            let worker_tx = self.sub_q.clone();
            let worker_h = thread::spawn(move || {
                println!("starting worker: {i}");

                if let Err(msg) = DaemonKernel::sub_task_loop(worker_rx, worker_tx) {
                    eprintln!("sub task loop exited with err: {msg:?}");
                }

                eprintln!("warning worker has exited: {i}");
            });

            workers.push(worker_h);
        }

        loop {
            let fr_beg = Instant::now();
            self.drain_requests()?;

            if next_monitor_t > fr_beg {
                next_monitor_t = Instant::now() + Duration::from_secs(10);
                self.sub_task_monitor(&mut workers)?;
                self.sub_spin_config()?;
            }

            let fr_end_t = fr_beg.elapsed();

            if fr_end_t > fr_budget_ms {
                eprintln!("event loop blocked {}ms", fr_end_t.as_millis()); 
            }

            thread::sleep(fr_budget_ms.saturating_sub(fr_end_t));
        }
    }

    fn sub_spin_config(&self) -> Result<()> {
        if false {
            let cfg = config::read_cached_file()?;
            self.tx_cfg_q.send(cfg)
                .map_err(|err| { RunError::TxDisconnected(format!("[chan] receivers gone? {err:?}")) })?;
        }

        Ok(()) // TODO: fs notify on config change?
    }

    fn sub_task_monitor(&self, threads: &mut [JoinHandle<()>]) -> Result<()> {
        for thread in threads {
            if thread.is_finished() { // TODO: don't panic :)
                return Err(RunError::RxDisconnected("sub task".into()))
            }
        }

        Ok(())
    }

    fn sub_task_loop(task_rx: Receiver<Packet<EventReq>>, sub_q: Sender<Packet<EventRep>>) -> Result<()> {
        use EventReq as Ty;
        use std::process::{Command, Stdio};

        loop {
            let packet = task_rx.recv().expect("failed to work steal request");
            println!("daemon [wkr] [pkt]: {packet:?}");
            let Packet { nonce, msg, .. } = packet;

            match msg {
                Ty::ZfsListDataset(args) => {
                    println!("zfs list :: {args:?}");
                    let mut cmd = Command::new("zfs"); 

                    cmd.arg("list")
                       .arg("-p")
                       .arg("-Ho")
                       .arg("name,avail,used,usedsnap");

                    // TODO: cleaner way to do this?
                    cmd.stdin(Stdio::piped());
                    cmd.stdout(Stdio::piped());
                    cmd.stderr(Stdio::piped());

                    // set our conditional flags
                    if args.recursive { cmd.arg("-r"); }
                    if let Some(name) = args.name { cmd.arg(name); }
                    if let Some(depth) = args.depth {
                        cmd.arg("-d"); cmd.arg(format!("{depth}"));
                    }

                    // spawn subproc
                    let mut subproc = cmd.spawn()?;
                    let status = subproc.wait()?;

                    if !status.success() {
                        eprintln!("zfs list failed");
                        return Ok(())
                    }

                    if let None = subproc.stdout {
                        eprintln!("no output from zfs?");
                        return Ok(())
                    }

                    // assume it came back as a bignasty string
                    let mut buf = String::new();

                    let buf_n = subproc.stdout
                                       .expect("subproc stdout not available")
                                       .read_to_string(&mut buf)?;

                    println!("({buf_n}b) response from ZFS");
                    println!("acknowledging {nonce:?}");
                    let new_ttl = Packet::calc_ttl(30);

                    let list = buf.lines()
                                  .map(|line| line.to_owned())
                                  .collect::<Vec<_>>();

                    let out_p = Packet::from_parts(nonce.0, new_ttl, EventRep::ZfsList { list });

                    sub_q.send(out_p)
                         .inspect_err(|err| eprintln!("daemon->ws error: {err:?}"))
                         .map_err(|_| RunError::Misc("ws reply queue disconnected".into()))?;
                },

                _ => { eprintln!("worker should not have been sent {msg:?}"); }
            }
        }
    }

    fn drain_requests(&mut self) -> Result<()> {
        use crossbeam_channel::TryRecvError;

        loop {
            match self.req_q.try_recv() {
                Ok(message) => { self.process_message(message)? },
                Err(TryRecvError::Empty) => { break },
                Err(_) => return Err(RunError::RxDisconnected("daemon req drain lost".into())),
            }
        }

        Ok(())
    }

    fn process_message(&mut self, event: Packet<EventReq>) -> Result<()> {
        use EventReq as Ty;

        println!("daemon [ in] [pkt]: {event:?}");
        let Packet { ref msg, .. } = event;

        match msg {
            Ty::Ping { msg } => { println!("ping: {msg}") },

            &Ty::Ident { version } => {
                if version != 0x1001 {
                    eprintln!("ident request for unknown version {:04x}", version);
                    return Err(RunError::Misc("ident version failure".into()));
                }

                println!("request to authenticate processed ;; starting v{version}");

                let event = EventRep::Ident { version, name: "hitomi".into() };
                let out_p = msg::build_packet(event);
                println!("daemon [out] [pkt]: {out_p:?}");

                self.sub_q
                    .send(out_p)
                    .map_err(|_| RunError::RxDisconnected("dmn->ws submission queue".into()))?;
            },

            Ty::ZfsListDataset(..) => {
                self.tx_wkr_q
                    .send(event)
                    .map_err(|_| RunError::RxDisconnected("dmn->wkr task queue".into()))?;
            }, 
        }

        Ok(())
    }

}
