//! A fixed pool of workers that run queued jobs.
//!
//! Each worker claims a job from the queue, evaluates it on a blocking thread
//! and records the outcome. Concurrency is bounded by the number of workers;
//! a submission wakes one of them, and each also polls once a second for retries
//! whose backoff has expired. On shutdown workers stop claiming, finish the job
//! they hold (up to a grace period) and exit; anything cut off stays
//! `processing` and is requeued at the next start.

use super::queue::{self, ClaimedJob};
use super::store::JobStore;
use super::INPUT_COUNT;
use crate::crypto::eval::EvalError;
use sqlx::SqlitePool;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{watch, Notify};
use tokio::task::JoinHandle;

const POLL_INTERVAL: Duration = Duration::from_secs(1);
const JANITOR_INTERVAL: Duration = Duration::from_secs(3600);

/// Computes a job's result from its inputs. CPU-bound; runs on a blocking thread.
pub type Processor =
    Arc<dyn Fn(&ClaimedJob, Vec<Vec<u8>>) -> Result<Vec<u8>, EvalError> + Send + Sync>;

/// Wakes a worker when a job is queued.
#[derive(Clone, Default)]
pub struct JobNotifier(Arc<Notify>);

impl JobNotifier {
    pub fn job_queued(&self) {
        self.0.notify_one();
    }
}

pub struct WorkerSettings {
    pub workers: usize,
    pub job_timeout: Duration,
    pub max_attempts: i64,
    pub retention_days: i64,
}

#[derive(Clone)]
struct Context {
    pool: SqlitePool,
    store: Arc<JobStore>,
    processor: Processor,
    notifier: JobNotifier,
    job_timeout: Duration,
    max_attempts: i64,
}

pub struct WorkerPool {
    notifier: JobNotifier,
    shutdown: watch::Sender<bool>,
    workers: Vec<JoinHandle<()>>,
    janitor: JoinHandle<()>,
}

impl WorkerPool {
    /// Requeues jobs a previous run left `processing`, then starts the workers.
    pub async fn start(
        pool: SqlitePool,
        store: Arc<JobStore>,
        processor: Processor,
        settings: WorkerSettings,
    ) -> sqlx::Result<Self> {
        let recovered = queue::recover_interrupted(&pool, settings.max_attempts).await?;
        if recovered != queue::Recovered::default() {
            log::warn!(
                "Recovered interrupted jobs: {} requeued, {} failed",
                recovered.requeued,
                recovered.failed
            );
        }

        let (shutdown, stop) = watch::channel(false);
        let notifier = JobNotifier::default();
        let ctx = Context {
            pool: pool.clone(),
            store: store.clone(),
            processor,
            notifier: notifier.clone(),
            job_timeout: settings.job_timeout,
            max_attempts: settings.max_attempts,
        };
        let workers = (0..settings.workers.max(1))
            .map(|_| tokio::spawn(work(ctx.clone(), stop.clone())))
            .collect();
        let janitor = tokio::spawn(janitor(pool, store, settings.retention_days, stop));
        Ok(WorkerPool {
            notifier,
            shutdown,
            workers,
            janitor,
        })
    }

    pub fn notifier(&self) -> JobNotifier {
        self.notifier.clone()
    }

    /// Stops claiming jobs and waits up to `grace` for running ones to finish.
    pub async fn shutdown(self, grace: Duration) {
        let _ = self.shutdown.send(true);
        self.janitor.abort();
        let aborts: Vec<_> = self.workers.iter().map(JoinHandle::abort_handle).collect();
        let drained = tokio::time::timeout(grace, async {
            for worker in self.workers {
                let _ = worker.await;
            }
        })
        .await;
        if drained.is_err() {
            log::warn!("Jobs still running after {grace:?}; they will be requeued at next start");
            aborts.iter().for_each(|a| a.abort());
        }
    }
}

/// Stops when shutdown is requested or the [`WorkerPool`] is dropped.
async fn work(ctx: Context, mut stop: watch::Receiver<bool>) {
    loop {
        let idle = match queue::claim_next(&ctx.pool).await {
            Ok(Some(job)) => {
                run(&ctx, job).await;
                false
            }
            Ok(None) => true,
            Err(e) => {
                log::error!("Failed to claim a job: {e}");
                true
            }
        };
        if idle {
            tokio::select! {
                _ = ctx.notifier.0.notified() => {}
                _ = tokio::time::sleep(POLL_INTERVAL) => {}
                // A send (shutdown) or a closed channel (pool dropped).
                _ = stop.changed() => {}
            }
        }
        if *stop.borrow() || stop.has_changed().is_err() {
            return;
        }
    }
}

/// How an attempt ended.
enum Outcome {
    Done(Vec<u8>),
    /// Final; the message is shown to the job's owner.
    Rejected(String),
    /// Possibly transient; retried while attempts remain.
    Error(String),
    /// Timed out; already recorded as failed (the result of recording it).
    TimedOut(sqlx::Result<bool>),
}

async fn run(ctx: &Context, job: ClaimedJob) {
    let id = job.id.as_str();
    // `finished`: the job reached a final state, so its inputs can go.
    let (recorded, finished) = match attempt(ctx, &job).await {
        Outcome::Done(result) => match ctx.store.write_result(id, &result) {
            Ok(()) => (queue::complete(&ctx.pool, id, result.len()).await, true),
            Err(e) => retry_or_fail(ctx, &job, format!("storing the result: {e}")).await,
        },
        Outcome::Rejected(message) => (queue::fail(&ctx.pool, id, &message).await, true),
        Outcome::Error(detail) => retry_or_fail(ctx, &job, detail).await,
        Outcome::TimedOut(recorded) => (recorded, true),
    };

    match recorded {
        Ok(true) if finished => {
            if let Err(e) = ctx.store.remove_inputs(id, INPUT_COUNT) {
                log::error!("Failed to delete inputs of job {id}: {e}");
            }
        }
        Ok(true) => {}
        // The job (or its owner's account) was deleted while it ran.
        Ok(false) => ctx.store.remove_logged(id),
        // Left `processing`; requeued at the next start.
        Err(e) => log::error!("Failed to record the outcome of job {id}: {e}"),
    }
}

/// Requeues the job if it has attempts left, else fails it. Returns the result of
/// recording that and whether the job is now finished.
async fn retry_or_fail(
    ctx: &Context,
    job: &ClaimedJob,
    detail: String,
) -> (sqlx::Result<bool>, bool) {
    log::error!("Job {} attempt {} failed: {detail}", job.id, job.attempts);
    if job.attempts < ctx.max_attempts {
        // The backoff is noticed by the workers' polling; nobody needs waking.
        (
            queue::retry_later(&ctx.pool, &job.id, job.attempts).await,
            false,
        )
    } else {
        (
            queue::fail(&ctx.pool, &job.id, "Internal error").await,
            true,
        )
    }
}

async fn attempt(ctx: &Context, job: &ClaimedJob) -> Outcome {
    let inputs = match ctx.store.read_inputs(&job.id, INPUT_COUNT) {
        Ok(inputs) => inputs,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Outcome::Rejected("Job inputs are no longer available".into())
        }
        Err(e) => return Outcome::Error(format!("reading inputs: {e}")),
    };

    let processor = ctx.processor.clone();
    let claimed = job.clone();
    let mut task = tokio::task::spawn_blocking(move || processor(&claimed, inputs));
    let finished = tokio::time::timeout(ctx.job_timeout, &mut task).await;

    let joined = match finished {
        Ok(joined) => joined,
        Err(_) => {
            // A blocking thread cannot be cancelled: record the timeout now, but
            // keep this worker busy until the thread ends so the number of
            // running evaluations never exceeds the number of workers.
            let message = format!(
                "Timed out after {} seconds",
                ctx.job_timeout.as_secs().max(1)
            );
            let recorded = queue::fail(&ctx.pool, &job.id, &message).await;
            let _ = task.await;
            return Outcome::TimedOut(recorded);
        }
    };

    match joined {
        Ok(Ok(result)) => Outcome::Done(result),
        Ok(Err(EvalError::InvalidInput(message))) => Outcome::Rejected(message),
        Ok(Err(EvalError::Internal(detail))) => Outcome::Error(detail),
        Err(join_error) => Outcome::Error(format!("evaluation panicked: {join_error}")),
    }
}

async fn janitor(
    pool: SqlitePool,
    store: Arc<JobStore>,
    retention_days: i64,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        match queue::purge_finished(&pool, retention_days).await {
            Ok(ids) => {
                if !ids.is_empty() {
                    log::info!(
                        "Deleted {} jobs older than {retention_days} days",
                        ids.len()
                    );
                }
                ids.iter().for_each(|id| store.remove_logged(id));
            }
            Err(e) => log::error!("Failed to purge old jobs: {e}"),
        }
        tokio::select! {
            _ = tokio::time::sleep(JANITOR_INTERVAL) => {}
            _ = stop.changed() => return,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::queue::test_support::*;
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Harness {
        pool: SqlitePool,
        store: Arc<JobStore>,
        dir: std::path::PathBuf,
    }

    impl Harness {
        async fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("heaas-worker-{}", uuid::Uuid::new_v4()));
            Harness {
                pool: test_pool().await,
                store: Arc::new(JobStore::new(&dir).unwrap()),
                dir,
            }
        }

        async fn queue(&self) -> String {
            let id = insert_pending(&self.pool, "add").await;
            self.store
                .write_inputs(&id, &[b"a".to_vec(), b"b".to_vec()])
                .unwrap();
            id
        }

        async fn start(&self, processor: Processor, timeout: Duration) -> WorkerPool {
            let settings = WorkerSettings {
                workers: 2,
                job_timeout: timeout,
                max_attempts: 3,
                retention_days: 7,
            };
            WorkerPool::start(self.pool.clone(), self.store.clone(), processor, settings)
                .await
                .unwrap()
        }

        async fn wait_until_finished(&self, id: &str) -> (String, i64, Option<String>) {
            for _ in 0..200 {
                let status = status_of(&self.pool, id).await;
                if status.0 == "completed" || status.0 == "failed" {
                    return status;
                }
                make_runnable(&self.pool, id).await;
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            panic!("job {id} did not finish");
        }
    }

    impl Drop for Harness {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn concat() -> Processor {
        Arc::new(|_, inputs| Ok(inputs.concat()))
    }

    #[tokio::test]
    async fn runs_queued_jobs_and_keeps_only_the_result() {
        let h = Harness::new().await;
        let workers = h.start(concat(), Duration::from_secs(10)).await;
        let id = h.queue().await;
        workers.notifier().job_queued();

        assert_eq!(h.wait_until_finished(&id).await.0, "completed");
        assert_eq!(h.store.read_result(&id).unwrap(), b"ab");
        assert!(h.store.read_inputs(&id, INPUT_COUNT).is_err());
        workers.shutdown(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn invalid_input_fails_without_retrying() {
        let h = Harness::new().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let processor: Processor = Arc::new(move |_, _| {
            counted.fetch_add(1, Ordering::SeqCst);
            Err(EvalError::InvalidInput("Input 1 is not valid".into()))
        });
        let workers = h.start(processor, Duration::from_secs(10)).await;
        let id = h.queue().await;

        let (status, attempts, message) = h.wait_until_finished(&id).await;
        assert_eq!((status.as_str(), attempts), ("failed", 1));
        assert_eq!(message.as_deref(), Some("Input 1 is not valid"));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        workers.shutdown(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn internal_errors_are_retried_then_fail() {
        let h = Harness::new().await;
        let calls = Arc::new(AtomicUsize::new(0));
        let counted = calls.clone();
        let processor: Processor = Arc::new(move |_, inputs| {
            // Fails twice, then succeeds on the third (last allowed) attempt.
            if counted.fetch_add(1, Ordering::SeqCst) < 2 {
                Err(EvalError::Internal("transient".into()))
            } else {
                Ok(inputs.concat())
            }
        });
        let workers = h.start(processor, Duration::from_secs(10)).await;
        let flaky = h.queue().await;
        assert_eq!(
            h.wait_until_finished(&flaky).await,
            ("completed".into(), 3, None)
        );
        workers.shutdown(Duration::from_secs(5)).await;

        let always: Processor = Arc::new(|_, _| Err(EvalError::Internal("broken".into())));
        let workers = h.start(always, Duration::from_secs(10)).await;
        let broken = h.queue().await;
        assert_eq!(
            h.wait_until_finished(&broken).await,
            ("failed".into(), 3, Some("Internal error".into()))
        );
        workers.shutdown(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn slow_jobs_time_out() {
        let h = Harness::new().await;
        let slow: Processor = Arc::new(|_, _| {
            std::thread::sleep(Duration::from_millis(400));
            Ok(vec![1])
        });
        let workers = h.start(slow, Duration::from_millis(50)).await;
        let id = h.queue().await;

        let (status, _, message) = h.wait_until_finished(&id).await;
        assert_eq!(status, "failed");
        assert!(message.unwrap().starts_with("Timed out"));
        workers.shutdown(Duration::from_secs(5)).await;
        assert!(h.store.read_result(&id).is_err(), "late result discarded");
    }

    #[tokio::test]
    async fn missing_inputs_fail_the_job() {
        let h = Harness::new().await;
        let workers = h.start(concat(), Duration::from_secs(10)).await;
        let id = insert_pending(&h.pool, "add").await;
        let (status, _, message) = h.wait_until_finished(&id).await;
        assert_eq!(status, "failed");
        assert_eq!(
            message.as_deref(),
            Some("Job inputs are no longer available")
        );
        workers.shutdown(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn jobs_interrupted_by_a_restart_are_run_again() {
        let h = Harness::new().await;
        let id = h.queue().await;
        // A previous server claimed the job and stopped before finishing it.
        let claimed = queue::claim_next(&h.pool).await.unwrap().unwrap();
        assert_eq!(claimed.id, id);

        let workers = h.start(concat(), Duration::from_secs(10)).await;
        assert_eq!(
            h.wait_until_finished(&id).await,
            ("completed".into(), 2, None)
        );
        workers.shutdown(Duration::from_secs(5)).await;
    }

    #[tokio::test]
    async fn shutdown_lets_the_running_job_finish() {
        let h = Harness::new().await;
        let slow: Processor = Arc::new(|_, inputs| {
            std::thread::sleep(Duration::from_millis(200));
            Ok(inputs.concat())
        });
        let workers = h.start(slow, Duration::from_secs(10)).await;
        let id = h.queue().await;
        workers.notifier().job_queued();
        while status_of(&h.pool, &id).await.0 == "pending" {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        workers.shutdown(Duration::from_secs(5)).await;
        assert_eq!(status_of(&h.pool, &id).await.0, "completed");
    }
}
