//! Durable homomorphic job processing: a queue in the `jobs` table, inputs and
//! results on disk, and a bounded pool of workers.

pub mod queue;
pub mod store;
pub mod worker;

use crate::crypto::eval::{evaluate, EvalError, Operation};
use crate::crypto::keys::{KeyStore, KeyStoreError};
use std::sync::Arc;
use worker::Processor;

/// Each job takes exactly two operands.
pub const INPUT_COUNT: usize = 2;

/// The production processor: loads the job's server key and evaluates.
pub fn evaluator(keys: Arc<KeyStore>) -> Processor {
    Arc::new(move |job, inputs| {
        let operation = Operation::parse(&job.operation)
            .ok_or_else(|| EvalError::Internal(format!("unknown operation {}", job.operation)))?;
        let key_id = job
            .key_id
            .as_deref()
            .ok_or_else(|| EvalError::InvalidInput("Server key no longer exists".into()))?;
        let key = keys.load(key_id).map_err(|e| match e {
            KeyStoreError::NotFound => {
                EvalError::InvalidInput("Server key no longer exists".into())
            }
            KeyStoreError::Invalid(m) => EvalError::Internal(format!("stored key is invalid: {m}")),
            KeyStoreError::Io(e) => EvalError::Internal(format!("key store: {e}")),
        })?;
        evaluate(&key, operation, &inputs[0], &inputs[1])
    })
}
