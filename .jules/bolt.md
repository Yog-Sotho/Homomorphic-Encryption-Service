## 2025-05-23 - Parallel HE Key Generation and Lock-Free Pool
**Learning:** Sequential generation of TFHE-rs keys (10-60s per slot) is a major server startup bottleneck. Additionally, wrapping thread-safe cryptographic keys in a Mutex unnecessarily serializes concurrent homomorphic operations.
**Action:** Use `tokio::task::spawn_blocking` to parallelize expensive CPU-bound setup and remove `Mutex` for types that are `Send + Sync`.

## 2025-05-24 - Reducing Serialization Overhead in HE Workflows
**Learning:** TFHE-rs ciphertexts are large (MBs), and performing multiple 'encrypt -> serialize -> deserialize -> operate -> serialize -> deserialize -> decrypt' cycles in a single request creates massive CPU and memory allocation overhead.
**Action:** Implement 'all-in-one' compute methods that keep ciphertexts as native in-memory objects throughout the request lifecycle, and offload all HE operations to 'spawn_blocking' to prevent async executor starvation.

## 2026-07-13 - Atomic Quota Enforcement with RETURNING
**Learning:** Performing 'SELECT quota -> logic -> UPDATE quota' in middleware creates unnecessary DB roundtrips and introduces race conditions. SQLite's 'INSERT...ON CONFLICT...RETURNING' allows for atomic increment-and-check in a single roundtrip.
**Action:** Use atomic SQL operations with 'RETURNING' for counters and state changes to reduce latency by 50% on hot paths.

## 2026-07-14 - Offloading High-Cost CPU Operations to spawn_blocking
**Learning:** CPU-intensive cryptography such as bcrypt hashing/verification (DEFAULT_COST=12, taking ~1.4s per call) blocks the active async worker thread in Actix-web, starving the executor and blocking concurrent requests.
**Action:** Always offload bcrypt operations to `tokio::task::spawn_blocking`. Use `.into_inner()` on request payloads (like `web::Json`) to move ownership and avoid unnecessary memory cloning when passing data to the blocking thread pool.
## 2026-07-14 - Offloading Bcrypt to Blocking Threads
**Learning:** Bcrypt hashing/verification is a CPU-bound operation taking ~100ms+. Running it directly in an async handler blocks the entire Actix-web worker thread, preventing it from processing other requests and leading to high tail latency under load.
**Action:** Always wrap `bcrypt::hash` and `bcrypt::verify` (including timing-attack dummy calls) in `tokio::task::spawn_blocking`.

## 2026-07-15 - Merging Sequential Database Queries with Joins
**Learning:** Performing multiple sequential database queries to populate a single response model (e.g. user details, OAuth connections, and daily usage counters) incurs substantial SQLite roundtrip, pool lock, and async context switching overhead. Using relational features like `LEFT JOIN` and aggregators like `GROUP_CONCAT` allows fetching all related entities atomically.
**Action:** Consolidate multi-query lookups into a single SQL statement using JOINs and split-aggregated values when populating compound models.
