use anyhow::Result;
use clap::{Args, Parser, Subcommand};
use data_encoding::BASE64;

use daemon::msg::*;

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


    Ok(match cli.command {
        Commands::Run(args) => entry_run(args)?,

        Commands::Test => entry_test()?,

        Commands::Genkey => entry_genkey()?,
        Commands::Pubkey => entry_pubkey()?,
    })
}

fn entry_test() -> Result<ExitCode> {
    use daemon::msg::EventReq;

    // let msg = EventReq::Ident { version: 0x1001 };
    let msg = EventReq::ZfsListDataset(ZfsListArgs {
        name: None,
        depth: None,
        ent_ty: ZfsListType::All,
        recursive: true,
    });

    let buf = serde_json::to_string(&msg)?;
    println!("json: {buf:?}");

    Ok(ExitCode::from(0))
}

fn entry_run(args: RunArgs) -> Result<ExitCode> {
    println!("starting daemon on: {}", args.listen_addr);

    daemon::run_command_queue()?;

    Ok(ExitCode::from(0))
}

fn entry_genkey() -> Result<ExitCode> {
    use snow::params::DHChoice;
    use snow::resolvers::{self, CryptoResolver};

    let resolver = resolvers::DefaultResolver::default();
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
        .expect(&format!("expected [32] bytes, got [{}]", stdin_bytes.len()));

    let resolver = resolvers::DefaultResolver::default();
    let mut dh = resolver.resolve_dh(&DHChoice::Curve25519).expect("crytpo curve unavailable");
    dh.set(sk_bytes);

    let output = BASE64.encode(dh.pubkey());
    println!("{output}");

    // TODO: pubkey for noise
    Ok(ExitCode::from(0))
}
