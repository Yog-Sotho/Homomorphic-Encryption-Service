//! `heaas`: generate TFHE keys, encrypt, compute on a HE Engine server, decrypt.
//!
//! ```sh
//! export HEAAS_URL=https://heaas.example.com HEAAS_EMAIL=you@example.com
//! heaas keygen                      # heaas-client.key (secret, 0600), heaas-server.key, heaas-public.key
//! heaas upload-key                  # prints the key id
//! heaas run --key-id <id> --op multiply 300 300               # prints 24464
//! heaas run --key-id <id> --op lt --type i32 -- -5 3           # prints true
//! heaas run --key-id <id> --op add --scalar 10 5               # 5 + 10 (10 sent in clear)
//! heaas run --key-id <id> --op sum --type u8 --prove 1 2 3     # proven inputs
//! heaas run --key-id <id> --expr "(a + b) * 3 < c ? a : b" 1 2 10   # a program
//! heaas run --key-id <id> --type u8 --expr "lookup(a, [1, 4, 9]), a + b" 2 5   # 9 and 7
//! ```
//!
//! With `heaas keygen --compression`, `run --compress` gets the results back as
//! one compressed list of ~2 KB instead of ~130–530 KB per value.
//!
//! Step by step: `encrypt` (or `prove`), `submit`, `wait`, `result`, `decrypt`.

use clap::{Parser, Subcommand};
use heaas_sdk::api::CreateJobRequest;
use heaas_sdk::program::{CheckedProgram, Program};
use heaas_sdk::{
    encode, fhe, parse_expression, Client, IntegerType, Operation, PlainValue, ValueType,
};
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

/// How a job's operands are given.
#[derive(clap::Args)]
struct Operands {
    #[arg(long)]
    key_id: String,
    /// One operation.
    #[arg(long, required_unless_present = "expr", conflicts_with = "expr")]
    op: Option<Operation>,
    /// A program, written as an expression over the inputs a, b, c, …, e.g.
    /// "(a + b) * 3 < c ? a : b" (see `heaas_core::parse_expression`).
    #[arg(long, conflicts_with = "scalar")]
    expr: Option<String>,
    /// The inputs' type.
    #[arg(long = "type", default_value = "u16")]
    integer_type: IntegerType,
    /// A plaintext right-hand operand (the server sees it).
    #[arg(long, allow_hyphen_values = true)]
    scalar: Option<String>,
    /// Return the results as one compressed list (the key must be made with
    /// `keygen --compression`).
    #[arg(long)]
    compress: bool,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a key pair locally. Only the server and public keys are ever uploaded.
    Keygen {
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
        #[arg(long, default_value = "heaas-server.key")]
        server_key: PathBuf,
        #[arg(long, default_value = "heaas-public.key")]
        public_key: PathBuf,
        /// Also make compression keys, so jobs can return compressed results
        /// (the server key grows from ~60 MB to ~106 MB).
        #[arg(long)]
        compression: bool,
        /// Replace existing key files.
        #[arg(long)]
        force: bool,
    },
    /// Register a compressed server key (and its public key, if the file exists); prints its id.
    UploadKey {
        #[arg(long, default_value = "heaas-server.key")]
        server_key: PathBuf,
        #[arg(long, default_value = "heaas-public.key")]
        public_key: PathBuf,
    },
    /// List your registered server keys.
    Keys,
    /// Delete a registered server key.
    DeleteKey { key_id: String },
    /// Encrypt a value into a ciphertext file.
    Encrypt {
        #[arg(allow_hyphen_values = true)]
        value: String,
        #[arg(long = "type", default_value = "u16")]
        integer_type: IntegerType,
        #[arg(long, short)]
        out: PathBuf,
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
    },
    /// Encrypt values into one list with a proof that it is well formed, for `submit --proven`.
    Prove {
        #[arg(long)]
        key_id: String,
        #[arg(long = "type", default_value = "u16")]
        integer_type: IntegerType,
        #[arg(long, short)]
        out: PathBuf,
        /// The public key uploaded for `key_id`.
        #[arg(long, default_value = "heaas-public.key")]
        public_key: PathBuf,
        #[arg(required = true, allow_hyphen_values = true)]
        values: Vec<String>,
    },
    /// Queue a job on ciphertext files (or one proven list); prints the job id.
    Submit {
        #[command(flatten)]
        operands: Operands,
        /// A proven list from `heaas prove`, instead of ciphertext files.
        #[arg(long, conflicts_with = "inputs")]
        proven: Option<PathBuf>,
        inputs: Vec<PathBuf>,
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
        /// Which result, for a program with several (0-based).
        #[arg(long, default_value_t = 0)]
        output: usize,
        #[arg(long, short)]
        out: PathBuf,
    },
    /// Decrypt a ciphertext file; prints the value (one per line for a
    /// compressed list).
    Decrypt {
        ciphertext: PathBuf,
        /// The ciphertext's type: a job's `result_type` (`bool` for
        /// comparisons). For a compressed list, its `result_types`, e.g. `u8,bool`.
        #[arg(long = "type", value_delimiter = ',', default_value = "u16")]
        value_types: Vec<ValueType>,
        /// The file is a compressed list of results (`compressed_results`).
        #[arg(long)]
        compressed: bool,
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
        /// Needed to unpack a compressed list.
        #[arg(long, default_value = "heaas-server.key")]
        server_key: PathBuf,
    },
    /// Encrypt values, compute on the server and decrypt the result.
    Run {
        #[command(flatten)]
        operands: Operands,
        /// Send the inputs as one proven list, made with the public key uploaded for the key.
        #[arg(long)]
        prove: bool,
        #[arg(long, default_value = "heaas-public.key")]
        public_key: PathBuf,
        #[arg(required = true, allow_hyphen_values = true)]
        values: Vec<String>,
        #[arg(long, default_value = "heaas-client.key")]
        client_key: PathBuf,
        /// Needed with --compress, to unpack the results.
        #[arg(long, default_value = "heaas-server.key")]
        server_key: PathBuf,
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

fn parse_values(ty: IntegerType, values: &[String]) -> Result<Vec<i128>, String> {
    values.iter().map(|v| ty.parse_value(v)).collect()
}

/// The operation, or the program, a job runs.
struct Plan {
    operation: Operation,
    program: Option<(Program, CheckedProgram)>,
}

impl Operands {
    /// Checks the operation or compiles the expression, for `inputs` encrypted
    /// inputs (`None`: not known here, e.g. a proven list; the server checks).
    fn plan(&self, inputs: Option<usize>) -> Result<Plan, String> {
        let scalar = self.scalar.is_some();
        match (&self.op, &self.expr) {
            (Some(op), _) => {
                if let Some(inputs) = inputs {
                    op.check_operands(inputs, scalar)?;
                }
                Ok(Plan {
                    operation: *op,
                    program: None,
                })
            }
            (None, Some(expr)) => {
                let compiled = parse_expression(expr)?;
                let inputs = inputs.unwrap_or(compiled.input_count);
                if compiled.input_count != inputs {
                    return Err(format!(
                        "the expression reads {} input(s), but {inputs} were given",
                        compiled.input_count
                    ));
                }
                let checked = compiled.program.check(self.integer_type, inputs)?;
                Ok(Plan {
                    operation: Operation::Program,
                    program: Some((compiled.program, checked)),
                })
            }
            (None, None) => Err("give --op or --expr".into()),
        }
    }

    fn request(
        &self,
        plan: &Plan,
        inputs: Vec<String>,
        proven_inputs: Option<String>,
    ) -> CreateJobRequest {
        CreateJobRequest {
            key_id: self.key_id.clone(),
            operation: plan.operation,
            integer_type: self.integer_type,
            inputs,
            proven_inputs,
            scalar: self.scalar.clone(),
            program: plan.program.as_ref().map(|(program, _)| program.clone()),
            compress_results: self.compress,
        }
    }
}

/// The decompressed server key in `path`, for unpacking compressed results.
fn load_server_key(path: &Path) -> Result<tfhe::ServerKey, Box<dyn std::error::Error>> {
    let bytes = std::fs::read(path).map_err(|e| {
        format!(
            "{}: {e} (compressed results need the server key)",
            path.display()
        )
    })?;
    Ok(fhe::server_key_from_bytes(&bytes)?.decompress())
}

fn print_values(values: &[PlainValue]) {
    for value in values {
        println!("{value}");
    }
}

async fn run(cli: Cli) -> Outcome {
    match &cli.command {
        Command::Keygen {
            client_key,
            server_key,
            public_key,
            compression,
            force,
        } => {
            for path in [client_key, server_key, public_key] {
                refuse_overwrite(path, *force)?;
            }
            eprintln!("Generating keys (this takes a while)…");
            let (secret, server) = if *compression {
                fhe::generate_compressing_keys()
            } else {
                fhe::generate_keys()
            };
            fhe::save_client_key(client_key, &secret)?;
            fhe::write_private(server_key, &fhe::server_key_bytes(&server)?)?;
            fhe::write_private(
                public_key,
                &fhe::public_key_bytes(&fhe::public_key(&secret))?,
            )?;
            eprintln!(
                "Secret key: {} (keep it; it cannot be recovered)\nServer and public keys: {}, {} (upload them with `heaas upload-key`)",
                client_key.display(),
                server_key.display(),
                public_key.display()
            );
        }
        Command::UploadKey {
            server_key,
            public_key,
        } => {
            let client = signed_in(&cli).await?;
            client.check_compatible().await?;
            let info = client.upload_key(std::fs::read(server_key)?).await?;
            if public_key.exists() && info.supports_proofs {
                client
                    .upload_public_key(&info.id, std::fs::read(public_key)?)
                    .await?;
            }
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
            integer_type,
            out,
            client_key,
        } => {
            let secret = fhe::load_client_key(client_key)?;
            let value = integer_type.parse_value(value)?;
            std::fs::write(out, fhe::encrypt_as(&secret, *integer_type, value)?)?;
        }
        Command::Prove {
            key_id,
            integer_type,
            out,
            public_key,
            values,
        } => {
            let values = parse_values(*integer_type, values)?;
            let public_key = fhe::public_key_from_bytes(&std::fs::read(public_key)?)?;
            let crs = Client::new(&cli.url)?.crs().await?;
            let list = fhe::prove(&public_key, &crs, key_id, *integer_type, &values)?;
            std::fs::write(out, list)?;
        }
        Command::Submit {
            operands,
            proven,
            inputs,
            idempotency_key,
        } => {
            let request = match proven {
                Some(path) => {
                    let plan = operands.plan(None)?;
                    operands.request(&plan, Vec::new(), Some(encode(&std::fs::read(path)?)))
                }
                None => {
                    let plan = operands.plan(Some(inputs.len()))?;
                    let inputs = inputs
                        .iter()
                        .map(|p| std::fs::read(p).map(|b| encode(&b)))
                        .collect::<Result<_, _>>()?;
                    operands.request(&plan, inputs, None)
                }
            };
            let client = signed_in(&cli).await?;
            let job = match idempotency_key {
                Some(key) => client.submit_job_idempotent(&request, key).await?,
                None => client.submit_job(&request).await?,
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
        Command::Result {
            job_id,
            output,
            out,
        } => {
            let bytes = signed_in(&cli)
                .await?
                .result_output(job_id, *output)
                .await?;
            std::fs::write(out, bytes)?;
        }
        Command::Decrypt {
            ciphertext,
            value_types,
            compressed,
            client_key,
            server_key,
        } => {
            let secret = fhe::load_client_key(client_key)?;
            let bytes = std::fs::read(ciphertext)?;
            if *compressed {
                let server = load_server_key(server_key)?;
                print_values(&fhe::decrypt_compressed(
                    &secret,
                    &server,
                    &bytes,
                    value_types,
                )?);
            } else {
                let [value_type] = value_types.as_slice() else {
                    return Err("give one --type (several only with --compressed)".into());
                };
                println!("{}", fhe::decrypt_as(&secret, *value_type, &bytes)?);
            }
        }
        Command::Run {
            operands,
            prove,
            public_key,
            values,
            client_key,
            server_key,
            timeout,
        } => {
            let ty = operands.integer_type;
            let values = parse_values(ty, values)?;
            let scalar = operands
                .scalar
                .as_deref()
                .map(|s| ty.parse_value(s))
                .transpose()?;
            let plan = operands.plan(Some(values.len()))?;
            let secret = fhe::load_client_key(client_key)?;
            // Loaded first, so a missing file fails before anything is queued.
            let server = operands
                .compress
                .then(|| load_server_key(server_key))
                .transpose()?;
            let client = signed_in(&cli).await?;
            client.check_compatible().await?;
            let request = if *prove {
                let public_key = fhe::public_key_from_bytes(&std::fs::read(public_key)?)?;
                let crs = client.crs().await?;
                let list = fhe::prove(&public_key, &crs, &operands.key_id, ty, &values)?;
                operands.request(&plan, Vec::new(), Some(encode(&list)))
            } else {
                let inputs = values
                    .iter()
                    .map(|&v| fhe::encrypt_as(&secret, ty, v).map(|b| encode(&b)))
                    .collect::<Result<_, _>>()?;
                operands.request(&plan, inputs, None)
            };
            let job = client.submit_job(&request).await?;
            let job = client.wait(&job.id, Duration::from_secs(*timeout)).await?;
            let results = client.results(&job).await?;
            let types = job.output_types();
            let decrypted = match &server {
                Some(server) => fhe::decrypt_compressed(&secret, server, &results[0], &types)?,
                None => results
                    .iter()
                    .zip(&types)
                    .map(|(bytes, &ty)| fhe::decrypt_as(&secret, ty, bytes))
                    .collect::<Result<_, _>>()?,
            };
            let expected = match &plan.program {
                Some((_, checked)) => checked.eval_plain(&values),
                None => {
                    let operands_plain: Vec<i128> = values.iter().copied().chain(scalar).collect();
                    vec![plan.operation.apply_plain(ty, &operands_plain)]
                }
            };
            if decrypted != expected {
                let show = |v: &[PlainValue]| {
                    v.iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                };
                return Err(format!(
                    "decrypted {}, but the expected result is {}: the key id may not belong to {}",
                    show(&decrypted),
                    show(&expected),
                    client_key.display()
                )
                .into());
            }
            print_values(&decrypted);
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
