use blinkedblist::List as Blist;

use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use crate::daemon::ws::start_socket_thread;
use err::*;
use msg::*;

pub mod err;
pub mod msg;
mod ws;

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

#[allow(unreachable_code)]
pub fn run_command_queue() -> Result<String> {
    println!("booting command queue");

    let dmn_init = DaemonInit::new();

    let thread_evt = thread::spawn(move || {
        let mut kernel = dmn_init.kernel;
        match kernel.event_loop() {
            Err(err) => Err(RunError::Misc(format!("{err:?}"))),
            Ok(_) => Ok(()),
        }
    });

    let ws_init = ws::WsInit {
        name: "hitomi".into(), // TODO: config
        req_tx: dmn_init.tx_req_q.clone(),
        rep_tx: dmn_init.tx_rep_q.clone(),
        rep_rx: dmn_init.rx_sub_q,
    };

    let mut ratchet_ws = Ratchet::new();
    let mut thread_ws = thread::spawn(move || {
        ws::start_socket_thread(ws_init)
    });

    loop {
        thread::sleep(Duration::from_millis(1000));

        if thread_ws.is_finished() {
            let ws_result = thread_ws.join()
                .inspect_err(|err| { eprintln!("w/s thread panic: {err:?}") })
                .ok().expect("ws panic exit"); // TODO: supervisor trap exit

            let rx_rep_q = ws_result
                .inspect_err(|err| { eprintln!("w/s fatal error: {err:?}") })
                .ok().expect("ws fatal exit"); // TODO: supervisor trap exit

            // apply backoff
            thread::sleep(ratchet_ws.wait());

            // attempt to reboot w/ our reclaimed submission queue
            let ws_init = ws::WsInit {
                name: "hitomi".into(), // TODO: config
                req_tx: dmn_init.tx_req_q.clone(),
                rep_tx: dmn_init.tx_rep_q.clone(),
                rep_rx: rx_rep_q,
            };

            thread_ws = thread::spawn(move || {
                start_socket_thread(ws_init)
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

    todo!("command queue supervisor exited unexpectedly");
}

#[allow(dead_code)]
pub struct DaemonKernel {
    req_q: Receiver<EventReq>,
    sub_q: SyncSender<EventRep>,

    pending: Blist<CorrelationId>,
}

pub struct DaemonInit {
    kernel: DaemonKernel,

    tx_req_q: SyncSender<EventReq>,
    tx_rep_q: SyncSender<EventRep>,
    rx_sub_q: Receiver<EventRep>,
}

impl DaemonInit {
    pub fn new() -> DaemonInit {
        let (tx_req_q, rx_req_q) = mpsc::sync_channel(8);
        let (tx_rep_q, rx_rep_q) = mpsc::sync_channel(1024);

        let fresh_instance = DaemonKernel {
            req_q: rx_req_q,
            sub_q: tx_rep_q.clone(),
            pending: Blist::new(),
        };


        Self {
            kernel: fresh_instance,
            tx_req_q: tx_req_q,
            tx_rep_q: tx_rep_q.clone(),
            rx_sub_q: rx_rep_q,
        }
    }
}

impl DaemonKernel {
    pub fn event_loop(&mut self) -> Result<()> {

        loop {
            let mut fr_start = Instant::now();
            let mut fr_budget_ms = Duration::from_millis(1000 / 100);

            self.drain_requests()?;
            fr_budget_ms = fr_budget_ms.saturating_sub(fr_start.elapsed());
            fr_start = Instant::now();

            if fr_budget_ms <= Duration::ZERO { eprintln!("dropped frame"); }
            thread::sleep(fr_budget_ms);
        }
    }

    fn drain_requests(&mut self) -> Result<()> {
        use mpsc::TryRecvError;

        loop {
            match self.req_q.try_recv() {
                Ok(message) => { self.process_message(message)? },
                Err(TryRecvError::Empty) => { break },
                Err(error) => return Err(error.into()),
            }
        }

        Ok(())
    }

    fn process_message(&mut self, event: EventReq) -> Result<()> {
        use EventReq as Ty;

        match event {
            Ty::Ping { msg } => { println!("ping: {msg}") },

            Ty::ZfsListDataset(args) => {
                println!("zfs list :: {args:?}");
            },

            Ty::Ident { version } => {
                if version != 0x1001 {
                    eprintln!("ident request for unknown version {:04x}", version);
                    return Err(RunError::Misc("ident version failure".into()));
                }

                println!("request to authenticate processed ;; starting v{version}");

                self.sub_q.send(EventRep::Ident { version, name: "hitomi".into() })
                    .inspect_err(|err| eprintln!("daemon->ws error: {err:?}"))
                    .map_err(|_| RunError::Misc("ws reply queue disconnected".into()))?;
            },
        }

        Ok(())
    }
}
