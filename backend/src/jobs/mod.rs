//! Durable homomorphic job processing: a queue in the `jobs` table, inputs and
//! results on disk, and a bounded pool of workers.

pub mod queue;
pub mod store;
pub mod worker;

use crate::crypto::eval::{evaluate, EvalError, Inputs, Job, Operation, ProofContext};
use crate::crypto::keys::{KeyStore, KeyStoreError};
use crate::crypto::params::proof_metadata;
use crate::crypto::proofs::Crs;
use std::sync::Arc;
use worker::Processor;

fn key_error(e: KeyStoreError, what: &str) -> EvalError {
    match e {
        KeyStoreError::NotFound => EvalError::InvalidInput(format!("{what} no longer exists")),
        KeyStoreError::Invalid(m) => EvalError::Internal(format!("stored {what} is invalid: {m}")),
        KeyStoreError::Io(e) => EvalError::Internal(format!("key store: {e}")),
    }
}

/// The production processor: loads the job's server key (and, for proven
/// inputs, its public key) and evaluates.
pub fn evaluator(keys: Arc<KeyStore>, crs: Arc<Crs>) -> Processor {
    Arc::new(move |job, inputs| {
        let operation = Operation::parse(&job.operation)
            .ok_or_else(|| EvalError::Internal(format!("unknown operation {}", job.operation)))?;
        let scalar = job
            .scalar
            .as_deref()
            .map(|s| job.integer_type.parse_value(s))
            .transpose()
            .map_err(|e| EvalError::Internal(format!("stored scalar: {e}")))?;
        let key_id = job
            .key_id
            .as_deref()
            .ok_or_else(|| EvalError::InvalidInput("Server key no longer exists".into()))?;
        let key = keys.load(key_id).map_err(|e| key_error(e, "Server key"))?;
        let public_key;
        let metadata = proof_metadata(key_id);
        let inputs = if job.proven {
            public_key = keys
                .load_public_key(key_id)
                .map_err(|e| key_error(e, "The key's public key"))?;
            Inputs::Proven {
                list: inputs.first().map(Vec::as_slice).unwrap_or_default(),
                proof: ProofContext {
                    crs: &crs.crs,
                    public_key: &public_key,
                    metadata: &metadata,
                },
            }
        } else {
            Inputs::Ciphertexts(&inputs)
        };
        let program = match &job.program {
            Some(program) => Some(
                program
                    .check(job.integer_type, job.input_count.max(0) as usize)
                    .map_err(|e| EvalError::Internal(format!("stored program: {e}")))?,
            ),
            None => None,
        };
        evaluate(
            &key,
            &Job {
                operation,
                integer_type: job.integer_type,
                scalar,
                inputs,
                program: program.as_ref(),
            },
        )
    })
}
