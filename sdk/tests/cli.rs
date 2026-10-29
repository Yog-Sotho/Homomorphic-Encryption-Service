//! The `heaas` binary, offline: key generation, encryption and decryption.
//! (The server-side flow is tested against a live server in the backend.)

use std::path::Path;
use std::process::{Command, Output};

fn heaas(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_heaas"))
        .args(args)
        .current_dir(dir)
        .env_remove("HEAAS_TOKEN")
        .env_remove("HEAAS_EMAIL")
        .output()
        .expect("heaas runs")
}

fn stdout(output: &Output) -> String {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout.clone()).unwrap()
}

#[test]
fn keys_are_made_locally_and_values_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let d = dir.path();

    stdout(&heaas(d, &["keygen"]));
    for file in ["heaas-client.key", "heaas-server.key", "heaas-public.key"] {
        let meta = std::fs::metadata(d.join(file)).unwrap();
        assert!(meta.len() > 1000, "{file}");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(meta.permissions().mode() & 0o777, 0o600, "{file}");
        }
    }

    // Existing keys are never replaced by accident: they cannot be recovered.
    let again = heaas(d, &["keygen"]);
    assert!(!again.status.success());
    assert!(String::from_utf8_lossy(&again.stderr).contains("--force"));

    stdout(&heaas(d, &["encrypt", "41", "--out", "a.ct"]));
    assert_eq!(stdout(&heaas(d, &["decrypt", "a.ct"])).trim(), "41");

    // Other types, negative values included; a type mismatch is refused.
    stdout(&heaas(
        d,
        &["encrypt", "--type", "i32", "-70000", "--out", "b.ct"],
    ));
    assert_eq!(
        stdout(&heaas(d, &["decrypt", "--type", "i32", "b.ct"])).trim(),
        "-70000"
    );
    assert!(!heaas(d, &["decrypt", "--type", "bool", "b.ct"])
        .status
        .success());
    let too_big = heaas(d, &["encrypt", "--type", "u8", "256", "--out", "c.ct"]);
    assert!(String::from_utf8_lossy(&too_big.stderr).contains("outside the u8 range"));

    // Garbage is refused, not decrypted to noise.
    std::fs::write(d.join("junk.ct"), b"not a ciphertext").unwrap();
    let junk = heaas(d, &["decrypt", "junk.ct"]);
    assert_eq!(junk.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&junk.stderr).starts_with("heaas: "));
}

#[test]
fn commands_that_need_an_account_say_how_to_sign_in() {
    let dir = tempfile::tempdir().unwrap();
    let output = heaas(dir.path(), &["keys"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("HEAAS_TOKEN"));

    let bad_op = heaas(
        dir.path(),
        &["submit", "--key-id", "k", "--op", "divide", "a", "b"],
    );
    assert_eq!(bad_op.status.code(), Some(2), "clap usage error");

    // The operand shape is checked before anything is encrypted or sent.
    let one_operand = heaas(dir.path(), &["run", "--key-id", "k", "--op", "add", "1"]);
    assert_eq!(one_operand.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&one_operand.stderr).contains("exactly 2"));
}
