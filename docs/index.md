---
hide:
  - navigation
---

<p align="center"><img src="images/banner.svg" alt="Homomorphic Encryption Engine" width="100%"></p>

# Homomorphic Encryption Engine

The HE Engine is a self-hosted server for computing on data that stays encrypted the
whole time. Users encrypt on their own devices, the server computes directly on the
encrypted values, and only the users can decrypt the results. The server never holds
a secret key, so neither it nor whoever runs it can read the inputs or the results.

It is built on [TFHE-rs](https://github.com/zama-ai/tfhe-rs), Zama's implementation of
fully homomorphic encryption, with a Rust backend, a Rust SDK and command-line tool,
and a web app that does all of its encryption in the browser.

![Encrypt on your device, compute on the server, decrypt on your device](images/how-it-works.svg)

<div class="grid cards" markdown>

-   :material-key-chain: **Your keys stay with you**

    ---

    Keys are made in the browser or with the CLI. The server only receives an
    evaluation key: enough to compute, never enough to decrypt.

-   :material-calculator-variant: **Real computation**

    ---

    Arithmetic, division, bitwise operations, comparisons, encrypted if-then-else and
    lookup tables on 8- to 64-bit integers, as single operations or whole programs.

-   :material-shield-check: **Proven inputs**

    ---

    Clients can attach a zero-knowledge proof that their inputs are well-formed
    encryptions; the server checks it before computing.

-   :material-server: **Built to run**

    ---

    Durable job queue, batches, idempotent submissions, metrics, health checks,
    backups and hardened container images.

</div>

## Start here

| If you want to… | Read |
|---|---|
| Use an instance from the dashboard | [User guide](user-guide.md) |
| Understand what is protected, and what is not | [How it works](how-it-works.md) |
| Compute from code or a terminal | [Using the API](api.md) and the [API reference](api-reference.md) |
| Check the exact cryptographic parameters | [Cryptographic parameters](parameters.md) |
| Run your own instance | [Self-hosting](self-hosting.md) |

## Quick start

Run an instance with Docker:

```sh
git clone https://github.com/Yog-Sotho/Homomorphic-Encryption-Service.git
cd Homomorphic-Encryption-Service
cp .env.example .env        # set JWT_SECRET and APP_BASE_URL
docker compose up -d --build
```

The app is then at `http://127.0.0.1:3000/heaas`. Users can also compute from a
terminal with the `heaas` CLI (prebuilt binaries are attached to each
[release](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/releases)):

```sh
export HEAAS_URL=https://<instance> HEAAS_EMAIL=you@example.com
heaas keygen && heaas upload-key                 # your keys, made locally
heaas run --key-id <id> --op multiply 300 300    # 24464 (300 × 300 mod 65536)
heaas run --key-id <id> --type u8 --expr "lookup(a, [1, 4, 9, 16]), a + b" 2 5   # 9, then 7
```

## Author and support

Written and maintained by [Yog-Sotho](https://github.com/Yog-Sotho). If the HE Engine
is useful to you, [sponsor it on GitHub](https://github.com/sponsors/Yog-Sotho) or send
a crypto tip: BTC and ETH to `yogsotho.blockchain` (an Unstoppable Domains name; check
the address your wallet resolves before sending), TRX to
`TBSVzUsQcof9f84aZGbn3wPGVAg3j4ttPv`.

## Licence

The HE Engine is released under the
[MIT licence](https://github.com/Yog-Sotho/Homomorphic-Encryption-Service/blob/master/LICENSE).
It depends on TFHE-rs (BSD-3-Clause-Clear, no patent grant): Zama states that
commercial use requires its patent licence.
