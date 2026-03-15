use clap::{Args, Command, Parser, Subcommand};
use data_encoding::BASE64;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use rand::rngs::StdRng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use ureq;

use std::io;

#[derive(Parser)]
#[command(version, about, long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Run(RunArgs),
    Genkey,
    Pubkey,
}

#[derive(Args)]
struct RunArgs {
    #[arg(short = 'l', long, default_value_t = format!("127.0.0.1:56100"))]
    listen_addr: String,

    #[arg(short = 'm', long)]
    master_addr: String,
    
}

#[derive(Args)]
struct PubkeyArgs {
    key: String,
}

#[derive(Serialize)]
struct Message<'a> {
    id: u64,
    kind: &'a str,
    body: &'a str,
}

fn main() {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run(args) => entry_run(args),

        Commands::Genkey => entry_genkey(),
        Commands::Pubkey => entry_pubkey(),
    }
}

fn entry_run(args: RunArgs) {
    println!("starting daemon on: {}", args.listen_addr);

    println!("sending test message to master: {}", args.master_addr);
    let url = format!("http://{}/api/test", args.master_addr);
    let whatever = run_call_master(&url).expect("could not call master");
    println!("got {whatever}");
}

fn run_call_master(endpoint: &str, ) -> Result<String, String> {
    // generate the json message
    let test_message = Message { id: 0, kind: "test", body: "hello, world." };

    let json_blob = serde_json::to_vec(&test_message)
        .map_err(|e| format!("error: {e:?}"))?;

    // load our crypto primitives
    let mut keybuf = String::new();

    io::stdin()
        .read_line(&mut keybuf)
        .expect("failed to read key from stdin");

    let stdin_bytes = BASE64.decode(keybuf.trim().as_bytes())
        .expect("failed to decode key from stdin");
    
    let sk_bytes: &[u8; 32] = stdin_bytes.as_slice().try_into()
        .expect(&format!("expected [32] bytes, got [{}]", stdin_bytes.len()));

    let sk = SigningKey::from_bytes(sk_bytes);


    // issue signed request
    let digest = Sha256::digest(&json_blob);
    println!("sending digest ({}): {digest:x}", json_blob.len());

    let sig = sk.sign(&digest);
    let enc = BASE64.encode(&sig.to_bytes());
    println!("{enc}");

    let mut resp = ureq::post(endpoint)
        .header("content-type", "application/json")
        .header("x-cyrene-sig", enc)
        .send(&json_blob)
        .map_err(|e| format!("req error: {e:?}"))?;

    let resp_body = resp.body_mut().read_to_string()
        .map_err(|e| format!("error: {e:?}"))?;

    Ok(resp_body)
}

fn entry_genkey() {
    let mut rng: StdRng = rand::make_rng();
    let sk = SigningKey::generate(&mut rng);
    println!("{}", BASE64.encode(sk.as_bytes()));
}

fn entry_pubkey() {
    let mut buf = String::new();

    io::stdin()
        .read_line(&mut buf)
        .expect("failed to read key from stdin");

    let stdin_bytes = BASE64.decode(buf.trim().as_bytes())
        .expect("failed to decode key from stdin");

    let sk_bytes: &[u8; 32] = stdin_bytes.as_slice().try_into()
        .expect(&format!("expected [32] bytes, got [{}]", stdin_bytes.len()));

    let sk = SigningKey::from_bytes(sk_bytes);
    let vk = sk.verifying_key();

    println!("{}", BASE64.encode(vk.as_bytes()));
}
