## 2025-05-23 - Parallel HE Key Generation and Lock-Free Pool
**Learning:** Sequential generation of TFHE-rs keys (10-60s per slot) is a major server startup bottleneck. Additionally, wrapping thread-safe cryptographic keys in a Mutex unnecessarily serializes concurrent homomorphic operations.
**Action:** Use `tokio::task::spawn_blocking` to parallelize expensive CPU-bound setup and remove `Mutex` for types that are `Send + Sync`.
