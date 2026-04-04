use daemon::msg::*;

use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use data_encoding::BASE64;
use tracing::{info, error};
use tracing_subscriber;

use std::io;
use std::process::ExitCode;

mod config;
mod daemon;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run(RunArgs),
    Test,
    Genkey,
    Pubkey,
}

#[derive(Args)]
struct RunArgs {
    #[arg(short = 'l', long, default_value_t = format!("127.0.0.1:56100"))]
    listen_addr: String,
}

#[derive(Args)]
struct PubkeyArgs {
    key: String,
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    tracing_subscriber::fmt::init();

    let cli_result = match cli.command {
        Commands::Run(args) => entry_run(args),

        Commands::Test => entry_test(),

        Commands::Genkey => entry_genkey(),
        Commands::Pubkey => entry_pubkey(),
    };

    if let Err(msg) = cli_result {
        error!("command exited with error: {msg:?}");
        return Err(msg);
    }

    Ok(cli_result.expect("should have been OK"))
}

fn entry_test() -> Result<ExitCode> {
    use bytes::Bytes;
    use daemon::msg::EventReq;
    use daemon::zfs;
    use std::fs::OpenOptions;

    use std::io::Read;

    let msg = EventReq::Ident { version: 0x1001 };
    let msg2 = EventReq::ZfsListDataset(ZfsListArgs {
        name: None,
        depth: None,
        ent_ty: ZfsListType::All,
        recursive: true,
    });

    let buf = serde_json::to_string(&msg)?;
    info!(buf, "json ident\n");

    let buf = serde_json::to_string(&msg2)?;
    info!(buf, "json list-datasets\n");

    let mut fo = OpenOptions::new();
    let mut f = fo.read(true).open("priv/zfs-list.txt")?;

    let mut io = Vec::new();
    let sz = f.read_to_end(&mut io)?;
    info!(size = sz, "read zfs listing from disk");

    let ds = zfs::parse_zfs_list(Bytes::from(io));
    info!(dbg = ?zfs::debug_print(&ds), "create zfs parse structure");

    Ok(ExitCode::from(0))
}

fn entry_run(args: RunArgs) -> Result<ExitCode> {
    info!("starting daemon on: {}", args.listen_addr);

    daemon::run_command_queue()?;

    Ok(ExitCode::from(0))
}

fn entry_genkey() -> Result<ExitCode> {
    use snow::params::DHChoice;
    use snow::resolvers::{self, CryptoResolver};

    let resolver = resolvers::DefaultResolver;
    let mut rng = resolver.resolve_rng().expect("crypto RNG unavailable");
    let mut dh = resolver.resolve_dh(&DHChoice::Curve25519).expect("crytpo curve unavailable");
    dh.generate(&mut *rng).expect("failed to generate key");

    let output = BASE64.encode(dh.privkey());
    println!("{output}");

    Ok(ExitCode::from(0))
}

fn entry_pubkey() -> Result<ExitCode> {
    use snow::params::DHChoice;
    use snow::resolvers::{self, CryptoResolver};

    let mut buf = String::new();

    io::stdin()
        .read_line(&mut buf)
        .expect("failed to read key from stdin");

    let stdin_bytes = BASE64.decode(buf.trim().as_bytes())
        .expect("failed to decode key from stdin");

    let sk_bytes: &[u8; 32] = stdin_bytes.as_slice().try_into()
        .unwrap_or_else(|_| panic!("expected [32] bytes, got [{}]", stdin_bytes.len()));

    let resolver = resolvers::DefaultResolver;
    let mut dh = resolver.resolve_dh(&DHChoice::Curve25519).expect("crytpo curve unavailable");
    dh.set(sk_bytes);

    let output = BASE64.encode(dh.pubkey());
    println!("{output}");

    // TODO: pubkey for noise
    Ok(ExitCode::from(0))
}
