//! `he-backend backup <dir>`: a consistent copy of everything the service keeps,
//! taken while it runs.
//!
//! - `<dir>/he_saas.db`: the database, via SQLite's `VACUUM INTO` (a
//!   transactionally consistent snapshot, safe alongside the running server).
//! - `<dir>/keys/`, `<dir>/jobs/`: the key and job stores. Their files are
//!   only ever replaced by atomic renames, so a copy never sees half a file;
//!   temporary files (dot-files) are skipped.
//!
//! Users' server keys are needed to finish their queued jobs, and the job store
//! holds results not yet fetched. The key store also holds users' public keys
//! and the proof CRS (`crs.bin`): restoring it keeps proofs made against that
//! CRS valid. None of it contains a secret key.
//!
//! Restore: stop the server, put the three back where `DATABASE_URL`,
//! `KEY_STORE_DIR` and `JOB_STORE_DIR` point, start it.

use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{ConnectOptions, Connection};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;

pub struct Sources {
    pub database_url: String,
    pub key_store_dir: PathBuf,
    pub job_store_dir: PathBuf,
}

impl Sources {
    /// The same variables (and defaults) the server reads.
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        let var = |name: &str, default: &str| {
            std::env::var(name)
                .ok()
                .filter(|v| !v.trim().is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        Sources {
            database_url: var("DATABASE_URL", "sqlite://./he_saas.db"),
            key_store_dir: var("KEY_STORE_DIR", "./data/keys").into(),
            job_store_dir: var("JOB_STORE_DIR", "./data/jobs").into(),
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Copied {
    pub key_files: usize,
    pub job_files: usize,
}

/// Writes the backup into `dest`, which must not exist yet (nothing is ever
/// overwritten).
pub async fn run(sources: &Sources, dest: &Path) -> Result<Copied, String> {
    fs::create_dir_all(dest.parent().unwrap_or(Path::new(".")))
        .map_err(|e| format!("creating {}: {e}", display(dest)))?;
    fs::create_dir(dest).map_err(|e| format!("creating {}: {e}", display(dest)))?;

    let options = SqliteConnectOptions::from_str(&sources.database_url)
        .map_err(|e| format!("DATABASE_URL: {e}"))?
        .create_if_missing(false);
    let mut conn = options
        .connect()
        .await
        .map_err(|e| format!("opening the database: {e}"))?;
    let snapshot = dest.join("he_saas.db");
    sqlx::query("VACUUM INTO ?")
        .bind(snapshot.to_string_lossy().into_owned())
        .execute(&mut conn)
        .await
        .map_err(|e| format!("snapshotting the database: {e}"))?;
    conn.close().await.ok();

    let key_files = copy_tree(&sources.key_store_dir, &dest.join("keys"))
        .map_err(|e| format!("copying the key store: {e}"))?;
    let job_files = copy_tree(&sources.job_store_dir, &dest.join("jobs"))
        .map_err(|e| format!("copying the job store: {e}"))?;
    Ok(Copied {
        key_files,
        job_files,
    })
}

fn display(path: &Path) -> String {
    path.display().to_string()
}

/// Copies regular files under `from` (recursively) into `to`, skipping
/// dot-files. A missing `from` copies nothing. Returns the number of files.
fn copy_tree(from: &Path, to: &Path) -> io::Result<usize> {
    fs::create_dir_all(to)?;
    let entries = match fs::read_dir(from) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(0),
        Err(e) => return Err(e),
    };
    let mut copied = 0;
    for entry in entries {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with('.') {
            continue;
        }
        let kind = entry.file_type()?;
        let target = to.join(entry.file_name());
        if kind.is_dir() {
            copied += copy_tree(&entry.path(), &target)?;
        } else if kind.is_file() {
            match fs::copy(entry.path(), &target) {
                Ok(_) => copied += 1,
                // Deleted since it was listed (a job removed meanwhile).
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
        }
    }
    Ok(copied)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn backs_up_a_live_database_and_both_stores() {
        let dir = std::env::temp_dir().join(format!("heaas-backup-{}", uuid::Uuid::new_v4()));
        let sources = Sources {
            database_url: format!("sqlite://{}?mode=rwc", dir.join("live.db").display()),
            key_store_dir: dir.join("keys"),
            job_store_dir: dir.join("jobs"),
        };
        fs::create_dir_all(&dir).unwrap();
        // The server's own connection (WAL mode), still open during the backup.
        let pool = crate::db::connect(&sources.database_url).await.unwrap();
        sqlx::query(
            "INSERT INTO users (id, email, password_hash) VALUES ('u1', 'a@example.com', '')",
        )
        .execute(&pool)
        .await
        .unwrap();
        fs::create_dir_all(dir.join("keys")).unwrap();
        fs::write(dir.join("keys/k1.bin"), b"key").unwrap();
        fs::write(dir.join("keys/.k2.bin.tmp"), b"half a key").unwrap();
        fs::create_dir_all(dir.join("jobs/j1")).unwrap();
        fs::write(dir.join("jobs/j1/out"), b"result").unwrap();

        let dest = dir.join("backups/first");
        let copied = run(&sources, &dest).await.unwrap();
        assert_eq!(
            copied,
            Copied {
                key_files: 1,
                job_files: 1
            }
        );
        assert_eq!(fs::read(dest.join("keys/k1.bin")).unwrap(), b"key");
        assert!(!dest.join("keys/.k2.bin.tmp").exists());
        assert_eq!(fs::read(dest.join("jobs/j1/out")).unwrap(), b"result");

        let restored =
            crate::db::connect(&format!("sqlite://{}", dest.join("he_saas.db").display()))
                .await
                .unwrap();
        let (email,): (String,) = sqlx::query_as("SELECT email FROM users WHERE id = 'u1'")
            .fetch_one(&restored)
            .await
            .unwrap();
        assert_eq!(email, "a@example.com");

        // An existing destination is never overwritten.
        assert!(run(&sources, &dest).await.is_err());
        pool.close().await;
        let _ = fs::remove_dir_all(&dir);
    }
}
