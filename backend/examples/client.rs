//! Minimal HEaaS API client: the whole flow from the README, compiled in CI.
//!
//! Generates a TFHE key pair locally, registers only the compressed server key,
//! encrypts two numbers, has the server multiply them, and decrypts the result.
//!
//! ```sh
//! HEAAS_URL=http://localhost:8080 HEAAS_EMAIL=you@example.com HEAAS_PASSWORD=... \
//!   cargo run --release --example client -- 300 300
//! ```

use base64::{engine::general_purpose::STANDARD, Engine as _};
use serde_json::{json, Value};
use std::time::Duration;
use tfhe::prelude::*;
use tfhe::safe_serialization::{safe_deserialize, safe_serialize};
use tfhe::{ClientKey, CompressedServerKey, ConfigBuilder, FheUint16};

/// Must match the server's `GET /api/he/params` limits.
const MAX_CIPHERTEXT_BYTES: u64 = 1 << 20;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| format!("set {name}").into())
}

async fn json_or_error(resp: reqwest::Response) -> Result<Value> {
    let status = resp.status();
    let body: Value = resp.json().await.unwrap_or(Value::Null);
    if !status.is_success() {
        return Err(format!("{status}: {}", body["message"]).into());
    }
    Ok(body)
}

fn encrypt(key: &ClientKey, value: u16) -> Result<String> {
    let mut bytes = Vec::new();
    safe_serialize(
        &FheUint16::encrypt(value, key),
        &mut bytes,
        MAX_CIPHERTEXT_BYTES,
    )?;
    Ok(STANDARD.encode(bytes))
}

#[tokio::main]
async fn main() -> Result<()> {
    let base = env("HEAAS_URL")?;
    let args: Vec<u16> = std::env::args()
        .skip(1)
        .map(|a| a.parse())
        .collect::<std::result::Result<_, _>>()?;
    let [a, b] = args[..] else {
        return Err("usage: client <a> <b>  (unsigned 16-bit integers)".into());
    };
    let http = reqwest::Client::new();

    // 1. Sign in.
    let login = http
        .post(format!("{base}/api/auth/login"))
        .json(&json!({ "email": env("HEAAS_EMAIL")?, "password": env("HEAAS_PASSWORD")? }))
        .send()
        .await?;
    let token = json_or_error(login).await?["token"]
        .as_str()
        .ok_or("no token")?
        .to_string();

    // 2. Generate keys locally. The client key never leaves this process.
    let client_key = ClientKey::generate(ConfigBuilder::default());
    let mut server_key = Vec::new();
    safe_serialize(
        &CompressedServerKey::new(&client_key),
        &mut server_key,
        1 << 30,
    )?;

    // 3. Register only the compressed server (evaluation) key.
    let upload = http
        .post(format!("{base}/api/keys"))
        .bearer_auth(&token)
        .header("Content-Type", "application/octet-stream")
        .body(server_key)
        .send()
        .await?;
    let key_id = json_or_error(upload).await?["id"]
        .as_str()
        .ok_or("no key id")?
        .to_string();
    println!("registered server key {key_id}");

    // 4. Submit encrypted inputs. The Idempotency-Key makes a resend after a
    //    network error return the same job instead of running (and charging) twice.
    let submit = http
        .post(format!("{base}/api/compute/jobs"))
        .bearer_auth(&token)
        .header("Idempotency-Key", uuid::Uuid::new_v4().to_string())
        .json(&json!({
            "key_id": key_id,
            "operation": "multiply",
            "inputs": [encrypt(&client_key, a)?, encrypt(&client_key, b)?],
        }))
        .send()
        .await?;
    let job_id = json_or_error(submit).await?["id"]
        .as_str()
        .ok_or("no job id")?
        .to_string();

    // 5. Poll until done, then fetch the encrypted result and decrypt it locally.
    let job = loop {
        let resp = http
            .get(format!("{base}/api/compute/jobs/{job_id}"))
            .bearer_auth(&token)
            .send()
            .await?;
        let job = json_or_error(resp).await?;
        match job["status"].as_str() {
            Some("pending" | "processing") => tokio::time::sleep(Duration::from_millis(500)).await,
            _ => break job,
        }
    };
    if job["status"] != "completed" {
        return Err(format!("job failed: {}", job["error_message"]).into());
    }
    let resp = http
        .get(format!("{base}/api/compute/jobs/{job_id}/result"))
        .bearer_auth(&token)
        .send()
        .await?
        .error_for_status()?;
    let bytes = resp.bytes().await?;
    let result: FheUint16 = safe_deserialize(&bytes[..], MAX_CIPHERTEXT_BYTES)?;
    let value: u16 = result.decrypt(&client_key);

    println!("{a} × {b} mod 65536 = {value}");
    assert_eq!(value, a.wrapping_mul(b));
    Ok(())
}
