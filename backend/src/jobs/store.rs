//! Job inputs and results on disk: `<dir>/<job id>/{in0,in1,…,out,out1,…}`.
//!
//! Ciphertexts are ~132 KB each, so they live in files rather than in SQLite rows;
//! the `jobs` table keeps only metadata and sizes.

use crate::storage::write_atomic;
use std::fs;
use std::io;
use std::path::PathBuf;

fn input_file(index: usize) -> String {
    format!("in{index}")
}

/// `out` for the first result (as before programs had several), then `out1`, ….
fn result_file(index: usize) -> String {
    match index {
        0 => "out".to_string(),
        n => format!("out{n}"),
    }
}

pub struct JobStore {
    dir: PathBuf,
}

impl JobStore {
    pub fn new(dir: impl Into<PathBuf>) -> io::Result<Self> {
        let dir = dir.into();
        fs::create_dir_all(&dir)?;
        Ok(JobStore { dir })
    }

    pub fn probe_writable(&self) -> io::Result<()> {
        crate::storage::probe_writable(&self.dir)
    }

    /// Only UUIDs are accepted, so a job id can never name a path outside `dir`.
    fn job_dir(&self, job_id: &str) -> io::Result<PathBuf> {
        uuid::Uuid::parse_str(job_id)
            .map(|id| self.dir.join(id.hyphenated().to_string()))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "job id is not a UUID"))
    }

    pub fn write_inputs(&self, job_id: &str, inputs: &[Vec<u8>]) -> io::Result<()> {
        let dir = self.job_dir(job_id)?;
        fs::create_dir_all(&dir)?;
        inputs
            .iter()
            .enumerate()
            .try_for_each(|(i, bytes)| write_atomic(&dir.join(input_file(i)), bytes))
    }

    pub fn read_inputs(&self, job_id: &str, count: usize) -> io::Result<Vec<Vec<u8>>> {
        let dir = self.job_dir(job_id)?;
        (0..count)
            .map(|i| fs::read(dir.join(input_file(i))))
            .collect()
    }

    /// Writes the results; each file is written atomically, the first last, so
    /// a job with an `out` file has every result.
    pub fn write_results(&self, job_id: &str, results: &[Vec<u8>]) -> io::Result<()> {
        let dir = self.job_dir(job_id)?;
        fs::create_dir_all(&dir)?;
        results
            .iter()
            .enumerate()
            .rev()
            .try_for_each(|(i, bytes)| write_atomic(&dir.join(result_file(i)), bytes))
    }

    pub fn read_result(&self, job_id: &str, index: usize) -> io::Result<Vec<u8>> {
        fs::read(self.job_dir(job_id)?.join(result_file(index)))
    }

    /// Drops the inputs of a finished job; its result (if any) stays.
    pub fn remove_inputs(&self, job_id: &str, count: usize) -> io::Result<()> {
        let dir = self.job_dir(job_id)?;
        (0..count).try_for_each(|i| ignore_missing(fs::remove_file(dir.join(input_file(i)))))
    }

    /// Deletes everything stored for a job. Missing data is fine.
    pub fn remove(&self, job_id: &str) -> io::Result<()> {
        ignore_missing(fs::remove_dir_all(self.job_dir(job_id)?))
    }

    /// Removes a job's data, logging rather than returning failures: callers use
    /// this after the job's row is gone, when leftovers are only wasted space.
    pub fn remove_logged(&self, job_id: &str) {
        if let Err(e) = self.remove(job_id) {
            tracing::error!("Failed to delete stored data for job {job_id}: {e}");
        }
    }

    #[cfg(test)]
    pub fn has_data(&self, job_id: &str) -> bool {
        self.job_dir(job_id).map(|d| d.exists()).unwrap_or(false)
    }
}

fn ignore_missing(result: io::Result<()>) -> io::Result<()> {
    match result {
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_store() -> (JobStore, PathBuf) {
        let dir = std::env::temp_dir().join(format!("heaas-jobs-{}", uuid::Uuid::new_v4()));
        (JobStore::new(&dir).unwrap(), dir)
    }

    #[test]
    fn stores_reads_and_removes_job_data() {
        let (store, dir) = temp_store();
        let id = uuid::Uuid::new_v4().to_string();

        store
            .write_inputs(&id, &[b"a".to_vec(), b"bb".to_vec()])
            .unwrap();
        assert_eq!(
            store.read_inputs(&id, 2).unwrap(),
            [b"a".to_vec(), b"bb".to_vec()]
        );
        store
            .write_results(&id, &[b"out".to_vec(), b"second".to_vec()])
            .unwrap();
        store.remove_inputs(&id, 2).unwrap();
        assert!(store.read_inputs(&id, 2).is_err());
        assert_eq!(store.read_result(&id, 0).unwrap(), b"out");
        assert_eq!(store.read_result(&id, 1).unwrap(), b"second");
        assert!(store.read_result(&id, 2).is_err());

        store.remove(&id).unwrap();
        store.remove(&id).unwrap();
        assert!(!store.has_data(&id));
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn rejects_ids_that_are_not_uuids() {
        let (store, dir) = temp_store();
        for id in ["../escape", "", "a/b"] {
            assert!(store.write_inputs(id, &[b"x".to_vec()]).is_err());
            assert!(store.read_result(id, 0).is_err());
            assert!(store.remove(id).is_err());
        }
        assert_eq!(fs::read_dir(&dir).unwrap().count(), 0);
        fs::remove_dir_all(dir).unwrap();
    }
}
