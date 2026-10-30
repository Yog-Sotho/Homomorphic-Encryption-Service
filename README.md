<p align="center">
  <img src="docs/images/banner.svg" alt="Homomorphic Encryption Engine" width="100%">
</p>

<p align="center">
  <a href="https://yog-sotho.github.io/Homomorphic-Encryption-Service/"><strong>Documentation</strong></a> ·
  <a href="https://yog-sotho.github.io/Homomorphic-Encryption-Service/api-reference/"><strong>API reference</strong></a> ·
  <a href="https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/releases"><strong>Releases</strong></a> ·
  <a href="SUPPORT.md"><strong>Support</strong></a>
</p>

<p align="center">
  <a href="https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/actions/workflows/ci.yml"><img src="https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/actions/workflows/ci.yml/badge.svg?branch=master" alt="CI"></a>
  <a href="https://yog-sotho.github.io/Homomorphic-Encryption-Service/"><img src="https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/actions/workflows/docs.yml/badge.svg?branch=master" alt="Docs"></a>
  <a href="https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/releases/latest"><img src="https://img.shields.io/github/v/release/Yog-Sotho/Homomorphic-Encryption-Service?color=6366f1" alt="Latest release"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/licence-MIT-6366f1" alt="MIT licence"></a>
  <img src="https://img.shields.io/badge/TFHE--rs-1.8.2-6366f1" alt="TFHE-rs 1.8.2">
  <img src="https://img.shields.io/badge/API-OpenAPI%203.1-6366f1" alt="OpenAPI 3.1">
  <img src="https://img.shields.io/badge/status-pre--1.0-a855f7" alt="Status: pre-1.0">
</p>

The Homomorphic Encryption Engine (HE Engine) is a self-hosted server for computing on
data that stays encrypted the whole time. Its users encrypt on their own devices, the
engine computes directly on the encrypted values, and only the users can decrypt the
results. The server never holds a secret key, so neither it nor whoever runs it can
read the inputs or the results.

It is built on [TFHE-rs](https://github.com/zama-ai/tfhe-rs), Zama's implementation
of fully homomorphic encryption, with a Rust backend and a web app that does all of
its encryption in the browser.

## Who it is for

Teams and organisations that want a shared server to compute on sensitive numbers
without trusting that server with the data, and individuals who want to compute on a
cloud machine they do not fully trust. You run one instance; your users get
accounts on it. It is not a hosted product: there is nothing to subscribe to.

## Why the HE Engine

- **Your keys stay with you.** Keys are created in your browser or with the
  command-line tool. The server receives only an evaluation key, which lets it
  compute but never decrypt.
- **Real computation on encrypted data.** Arithmetic, division, bitwise
  operations, comparisons and sums on signed and unsigned integers from 8 to 64
  bits, using TFHE-rs's default parameters (128-bit security according to Zama).
- **Programs.** Write an expression such as `(a + b) * 3 < c ? a : b`: the server
  evaluates every step on ciphertexts, including the encrypted if-then-else and
  lookup tables, and returns one or several encrypted results. With the SDK,
  results can come back compressed, about 2 KB instead of 130 to 530 KB each.
- **Proven inputs.** Clients can attach a zero-knowledge proof that their inputs are
  well-formed encryptions; the server checks it before computing.
- **Use it your way.** A web dashboard, a Rust SDK and command-line tool, or a
  documented HTTP API.
- **Built to run.** Durable job processing, monitoring, health checks, backups and
  hardened container images.

## How it works

![Encrypt on your device, compute on the server, decrypt on your device](docs/images/how-it-works.svg)

The server holds an *evaluation key*: enough to compute on your ciphertexts, never
enough to read them. [How the HE Engine works](docs/how-it-works.md) explains the keys, the
architecture and exactly what the server can and cannot learn.

## See it in action

![The HE Engine dashboard after multiplying two encrypted numbers](docs/images/dashboard.png)

The numbers are encrypted in the browser, multiplied on the server without being
decrypted, and the result is decrypted back in the browser.

## Quick start

Run your own instance with Docker:

```sh
cp .env.example .env        # set JWT_SECRET and APP_BASE_URL
docker compose up -d --build
```

The app is then available at `http://127.0.0.1:3000/heaas`. For HTTPS, configuration
and backups, see [Self-hosting](docs/self-hosting.md).

Prebuilt images are published with each [release](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/releases):
`ghcr.io/yog-sotho/he-engine-backend` and `ghcr.io/yog-sotho/he-engine-frontend`.

Your users can then also compute from a terminal with the `heaas` CLI (prebuilt
for Linux and macOS on the [releases page](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/releases), or
`cargo install --path sdk`):

```sh
export HEAAS_URL=https://<instance> HEAAS_EMAIL=you@example.com
heaas keygen && heaas upload-key                 # your keys, made locally
heaas run --key-id <id> --op multiply 300 300    # 24464 (300 × 300 mod 65536)
```

## Documentation

Everything below is also on the documentation site, **[https://yog-sotho.github.io/Homomorphic-Encryption-Service](https://yog-sotho.github.io/Homomorphic-Encryption-Service/)**.

| | |
|---|---|
| [User guide](docs/user-guide.md) | Using the dashboard, managing keys, troubleshooting |
| [How the HE Engine works](docs/how-it-works.md) | Keys, architecture, privacy guarantees and limits |
| [Using the API](docs/api.md) | HTTP API, Rust SDK and the `heaas` command-line tool |
| [API reference](https://yog-sotho.github.io/Homomorphic-Encryption-Service/api-reference/) | Every endpoint and schema, generated from the code |
| [Self-hosting](docs/self-hosting.md) | Deployment, configuration, monitoring, backups |
| [Cryptographic parameters](docs/parameters.md) | The exact TFHE parameters, generated from the code |
| [Changelog](CHANGELOG.md) | What changed in each release |

## Community

- **Questions and help:** [GitHub Discussions](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/discussions); see [SUPPORT.md](SUPPORT.md).
- **Bugs and feature requests:** [open an issue](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/issues/new/choose).
- **Contributing:** building, testing and the checks every change must pass are in
  [CONTRIBUTING.md](CONTRIBUTING.md). Everyone follows the [code of conduct](CODE_OF_CONDUCT.md).
- **Security:** report vulnerabilities privately; [SECURITY.md](SECURITY.md) has the
  threat model and how to report.

## Project status

The HE Engine is pre-1.0. It works end to end and is covered by unit, property,
integration and browser tests, with coverage measured in CI. Like all FHE systems,
it cannot prove that the server computed correctly;
[How the HE Engine works](docs/how-it-works.md#what-the-server-can-and-cannot-learn)
lists the limits. The latest code audit is in
[`docs/project/codebase_audit.md`](docs/project/codebase_audit.md).

## Licence

The HE Engine is released under the [MIT licence](LICENSE).

It depends on TFHE-rs, which is distributed under BSD-3-Clause-Clear and grants no
patent rights. Zama states that TFHE-rs is free for development, research,
prototyping and experimentation, and that **commercial use requires Zama's patent
licence**. Obtain that licence before any commercial use of a deployment.
