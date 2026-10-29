//! `heaas`: generate TFHE keys, encrypt, compute on a HE Engine server, decrypt.
//!
//! ```sh
//! export HEAAS_URL=https://heaas.example.com HEAAS_EMAIL=you@example.com
//! heaas keygen                      # heaas-client.key (secret, 0600) + heaas-server.key
//! heaas upload-key                  # prints the key id
//! heaas run --key-id <id> --op multiply 300 300   # prints 24464
//! ```
//!
//! Step by step: `encrypt`, `submit`, `wait`, `result`, `decrypt`.

use clap::{Parser, Subcommand};
use heaas_sdk::{fhe, Client, Operation};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[derive(Parser)]
#[command(
    name = "heaas",
    version,
    about = "Compute on encrypted data with a HE Engine server"
)]
struct Cli {
    /// The site's URL.
    #[arg(
        long,
        env = "HEAAS_URL",
        default_value = "http://127.0.0.1:8080",
        global = true
    )]
    url: String,
    /// An access token (e.g. from `heaas login`). Otherwise commands that need
    /// one sign in with HEAAS_EMAIL and HEAAS_PASSWORD (prompted if unset).
    #[arg(long, env = "HEAAS_TOKEN", hide_env_values = true, global = true)]
    token: Option<String>,
    #[arg(long, env = "HEAAS_EMAIL", global = true)]
    email: Option<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a key pair locally. Only the server key is ever uploaded.
    Keygen {
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
        #[arg(long, default_value = "heaas-server.key")]
        server_key: PathBuf,
        /// Replace existing key files.
        #[arg(long)]
        force: bool,
    },
    /// Register a compressed server key; prints its id.
    UploadKey {
        #[arg(long, default_value = "heaas-server.key")]
        server_key: PathBuf,
    },
    /// List your registered server keys.
    Keys,
    /// Delete a registered server key.
    DeleteKey { key_id: String },
    /// Encrypt a 16-bit unsigned integer into a ciphertext file.
    Encrypt {
        value: u16,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
    },
    /// Queue `op(a, b)` on two ciphertext files; prints the job id.
    Submit {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        op: Operation,
        a: PathBuf,
        b: PathBuf,
        /// Reuse to resubmit safely (the default is random).
        #[arg(long)]
        idempotency_key: Option<String>,
    },
    /// Wait for a job to finish.
    Wait {
        job_id: String,
        /// Seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// Save a completed job's encrypted result.
    Result {
        job_id: String,
        #[arg(long, short)]
        out: PathBuf,
    },
    /// Decrypt a ciphertext file; prints the value.
    Decrypt {
        ciphertext: PathBuf,
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
    },
    /// Encrypt two values, compute `op(a, b)` on the server and decrypt the result.
    Run {
        #[arg(long)]
        key_id: String,
        #[arg(long)]
        op: Operation,
        a: u16,
        b: u16,
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
        /// Seconds.
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
    /// List your jobs, newest first (one JSON object per line).
    Jobs {
        #[arg(long, default_value_t = 20)]
        limit: u32,
        #[arg(long)]
        cursor: Option<String>,
    },
    /// Show the server's parameters and check this tool is compatible.
    Params,
    /// Sign in and print an access token (for HEAAS_TOKEN).
    Login,
}

type Outcome = Result<(), Box<dyn std::error::Error>>;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("heaas: {e}");
            ExitCode::FAILURE
        }
    }
}

/// A client signed in with the token, or else the email and password.
async fn signed_in(cli: &Cli) -> Result<Client, Box<dyn std::error::Error>> {
    let client = Client::new(&cli.url)?;
    if let Some(token) = &cli.token {
        return Ok(client.with_token(token.clone()));
    }
    let email = cli
        .email
        .as_deref()
        .ok_or("set HEAAS_TOKEN, or HEAAS_EMAIL (and HEAAS_PASSWORD) to sign in")?;
    let password = match std::env::var("HEAAS_PASSWORD") {
        Ok(password) => password,
        Err(_) => rpassword::prompt_password(format!("Password for {email}: "))?,
    };
    client.login(email, &password).await?;
    Ok(client)
}

fn refuse_overwrite(path: &Path, force: bool) -> Outcome {
    if path.exists() && !force {
        return Err(format!("{} exists (use --force to replace it)", path.display()).into());
    }
    Ok(())
}

fn print_json(value: &impl serde::Serialize) -> Outcome {
    println!("{}", serde_json::to_string(value)?);
    Ok(())
}

async fn run(cli: Cli) -> Outcome {
    match &cli.command {
        Command::Keygen {
            client_key,
            server_key,
            force,
        } => {
            refuse_overwrite(client_key, *force)?;
            refuse_overwrite(server_key, *force)?;
            eprintln!("Generating keys (this takes a while)…");
            let (secret, server) = fhe::generate_keys();
            fhe::save_client_key(client_key, &secret)?;
            fhe::write_private(server_key, &fhe::server_key_bytes(&server)?)?;
            eprintln!(
                "Secret key: {} (keep it; it cannot be recovered)\nServer key: {} (upload it with `heaas upload-key`)",
                client_key.display(),
                server_key.display()
            );
        }
        Command::UploadKey { server_key } => {
            let client = signed_in(&cli).await?;
            client.check_compatible().await?;
            let info = client.upload_key(std::fs::read(server_key)?).await?;
            println!("{}", info.id);
        }
        Command::Keys => {
            for key in signed_in(&cli).await?.list_keys().await? {
                print_json(&key)?;
            }
        }
        Command::DeleteKey { key_id } => signed_in(&cli).await?.delete_key(key_id).await?,
        Command::Encrypt {
            value,
            out,
            client_key,
        } => {
            let secret = fhe::load_client_key(client_key)?;
            std::fs::write(out, fhe::encrypt(&secret, *value)?)?;
        }
        Command::Submit {
            key_id,
            op,
            a,
            b,
            idempotency_key,
        } => {
            let client = signed_in(&cli).await?;
            let (a, b) = (std::fs::read(a)?, std::fs::read(b)?);
            let job = match idempotency_key {
                Some(key) => client.submit_idempotent(key_id, *op, &a, &b, key).await?,
                None => client.submit(key_id, *op, &a, &b).await?,
            };
            println!("{}", job.id);
        }
        Command::Wait { job_id, timeout } => {
            let job = signed_in(&cli)
                .await?
                .wait(job_id, Duration::from_secs(*timeout))
                .await?;
            println!("{}", job.status);
        }
        Command::Result { job_id, out } => {
            let bytes = signed_in(&cli).await?.result(job_id).await?;
            std::fs::write(out, bytes)?;
        }
        Command::Decrypt {
            ciphertext,
            client_key,
        } => {
            let secret = fhe::load_client_key(client_key)?;
            println!("{}", fhe::decrypt(&secret, &std::fs::read(ciphertext)?)?);
        }
        Command::Run {
            key_id,
            op,
            a,
            b,
            client_key,
            timeout,
        } => {
            let secret = fhe::load_client_key(client_key)?;
            let client = signed_in(&cli).await?;
            client.check_compatible().await?;
            let (ca, cb) = (fhe::encrypt(&secret, *a)?, fhe::encrypt(&secret, *b)?);
            let result = client
                .compute(key_id, *op, &ca, &cb, Duration::from_secs(*timeout))
                .await?;
            let value = fhe::decrypt(&secret, &result)?;
            let expected = op.apply_plain(*a, *b);
            if value != expected {
                return Err(format!(
                    "decrypted {value}, but {op}({a}, {b}) is {expected}: the key id may not belong to {}",
                    client_key.display()
                )
                .into());
            }
            println!("{value}");
        }
        Command::Jobs { limit, cursor } => {
            let page = signed_in(&cli)
                .await?
                .list_jobs(cursor.as_deref(), Some(*limit))
                .await?;
            for job in &page.data {
                print_json(job)?;
            }
            if let Some(next) = page.next_cursor {
                eprintln!("More: --cursor {next}");
            }
        }
        Command::Params => {
            let client = Client::new(&cli.url)?;
            print_json(&client.check_compatible().await?)?;
        }
        Command::Login => {
            let client = signed_in(&cli).await?;
            println!("{}", client.token().unwrap_or_default());
        }
    }
    Ok(())
}
