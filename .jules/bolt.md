## 2025-05-23 - Parallel HE Key Generation and Lock-Free Pool
**Learning:** Sequential generation of TFHE-rs keys (10-60s per slot) is a major server startup bottleneck. Additionally, wrapping thread-safe cryptographic keys in a Mutex unnecessarily serializes concurrent homomorphic operations.
**Action:** Use `tokio::task::spawn_blocking` to parallelize expensive CPU-bound setup and remove `Mutex` for types that are `Send + Sync`.

## 2025-05-24 - Reducing Serialization Overhead in HE Workflows
**Learning:** TFHE-rs ciphertexts are large (MBs), and performing multiple 'encrypt -> serialize -> deserialize -> operate -> serialize -> deserialize -> decrypt' cycles in a single request creates massive CPU and memory allocation overhead.
**Action:** Implement 'all-in-one' compute methods that keep ciphertexts as native in-memory objects throughout the request lifecycle, and offload all HE operations to 'spawn_blocking' to prevent async executor starvation.
