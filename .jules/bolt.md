## 2025-05-23 - Parallel HE Key Generation and Lock-Free Pool
**Learning:** Sequential generation of TFHE-rs keys (10-60s per slot) is a major server startup bottleneck. Additionally, wrapping thread-safe cryptographic keys in a Mutex unnecessarily serializes concurrent homomorphic operations.
**Action:** Use `tokio::task::spawn_blocking` to parallelize expensive CPU-bound setup and remove `Mutex` for types that are `Send + Sync`.

## 2025-05-24 - Reducing Serialization Overhead in HE Workflows
**Learning:** TFHE-rs ciphertexts are large (MBs), and performing multiple 'encrypt -> serialize -> deserialize -> operate -> serialize -> deserialize -> decrypt' cycles in a single request creates massive CPU and memory allocation overhead.
**Action:** Implement 'all-in-one' compute methods that keep ciphertexts as native in-memory objects throughout the request lifecycle, and offload all HE operations to 'spawn_blocking' to prevent async executor starvation.

## 2026-07-13 - Atomic Quota Enforcement with RETURNING
**Learning:** Performing 'SELECT quota -> logic -> UPDATE quota' in middleware creates unnecessary DB roundtrips and introduces race conditions. SQLite's 'INSERT...ON CONFLICT...RETURNING' allows for atomic increment-and-check in a single roundtrip.
**Action:** Use atomic SQL operations with 'RETURNING' for counters and state changes to reduce latency by 50% on hot paths.

## 2026-07-14 - Offloading High-Latency bcrypt Operations
**Learning:** `bcrypt` hashing and verification (default cost) take ~1.4s per operation. Running these synchronously on the Actix-web event loop effectively serializes all concurrent requests during authentication spikes, causing massive latency for unrelated IO-bound tasks.
**Action:** Always offload `bcrypt::hash` and `bcrypt::verify` to `tokio::task::spawn_blocking` to preserve async executor throughput.
