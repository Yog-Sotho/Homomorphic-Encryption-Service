<!-- Generated from core/src/params.rs by `UPDATE_DOCS=1 cargo test -p heaas-core`; do not edit. -->
# Cryptographic parameters

Every key and ciphertext HE Engine accepts is made with these parameters; servers
reject keys and ciphertexts that do not conform to them. They are TFHE-rs's
defaults and Zama's dedicated compact-public-key parameters for proven inputs,
which HE Engine does not tune. Zama states that its default parameters
give at least 128 bits of security (Lattice Estimator, MATZOV cost model) with
a bootstrapping failure probability of at most 2^-128, chosen for the IND-CPA^D
model: see [Security and cryptography](https://docs.zama.org/tfhe-rs/get-started/security-and-cryptography).

| | |
|---|---|
| TFHE-rs release | `1.8.2` |
| Parameter set | `PARAM_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128` |
| Encrypted types | `FheUint8`, `FheUint16`, `FheUint32`, `FheUint64`, `FheInt8`, `FheInt16`, `FheInt32`, `FheInt64` (arithmetic modulo 2^bits) and `FheBool` (comparison results) |
| Blocks per integer | bits / 2 (each block holds 2 message bits and 2 carry bits) |
| Failure probability per PBS | 2^-129.581 |
| LWE dimension *n* | 918 |
| GLWE dimension *k* | 1 |
| Polynomial size *N* | 2048 |
| LWE noise | TUniform, bound 2^45 |
| GLWE noise | TUniform, bound 2^17 |
| PBS decomposition | base log 23, level 1 |
| Key-switch decomposition | base log 4, level 4 |
| Ciphertext modulus | `CiphertextModulus(2^64)` |
| Encryption key | `Big` |
| Public-key encryption | `PARAM_PKE_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`: LWE dimension 2048, TUniform, bound 2^17, RequiresCasting |
| Casting key switch | `PARAM_KEYSWITCH_MESSAGE_2_CARRY_2_KS_PBS_TUNIFORM_2M128`: base log 4, level 4, to `Small` |
| Zero-knowledge proofs | TFHE-rs compact PKE proofs (`V2`), CRS for 512 bits per list |
| Size limits | ciphertext ≤ 1048576 B, inputs per job ≤ 16 (≤ 9437184 B), proven list ≤ 1048576 B, public key ≤ 1048576 B, client key ≤ 67108864 B, compressed server key ≤ 1073741824 B (servers may accept less) |
