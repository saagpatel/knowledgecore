# KnowledgeCore

[![Rust](https://img.shields.io/badge/Rust-dea584?style=flat-square&logo=rust)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> Your documents, locally searchable with opt-in encryption — no cloud, no accounts, no compromise.

KnowledgeCore is a local-first knowledge vault for ingesting, indexing, and querying documents. Document content is stored in a BLAKE3-addressed object store with optional XChaCha20-Poly1305 encryption; metadata is stored in SQLite with optional SQLCipher encryption. CLI index rebuild uses LanceDB with deterministic byte-histogram embeddings and SQLite FTS5; desktop search uses case-insensitive substring matching. A trust and lineage layer tracks document provenance, authorship, and policy governance across devices.

## Features

- **Encrypted vault** — opt-in SQLCipher database encryption with PBKDF2-HMAC-SHA512, and XChaCha20-Poly1305 object encryption with Argon2id key derivation
- **Vector index** — LanceDB with Apache Arrow; CLI rebuild uses deterministic byte-histogram embeddings
- **Content addressing** — BLAKE3 hashes ensure integrity and deduplication
- **PDF extraction** — pdfium-render for high-fidelity document parsing
- **CLI + desktop** — `kc_cli` plus a Tauri 2 desktop app sharing Rust core services
- **Recovery escrow** — AWS, Azure, GCP, and HSM adapters use local filesystem emulation only; AWS SDK dependencies are present, but live AWS calls are not implemented

## Quick Start

### Prerequisites
- Current stable Rust and Cargo (the Rust CI lane uses `stable`; 2021 edition)
- Protobuf compiler (`protoc`) for the Rust dependency build; CI installs `protobuf-compiler`
- Node.js 24.x and pnpm (desktop app only; matches the UI CI runtime)

For safe contributor checks, focused tests, and desktop-specific constraints,
see [CONTRIBUTING.md](CONTRIBUTING.md#verification). Use disposable fixture data
for verification; the scan-folder example below reads the checked-in golden corpus.

### Installation
```bash
cargo build --locked --release -p kc_cli
```

### Usage
```bash
# Initialize a new vault
./target/release/kc_cli vault init ./my-vault my-vault

# Ingest documents
./target/release/kc_cli ingest scan-folder \
  ./my-vault ./fixtures/golden_corpus/v1 local

# Rebuild the vector and full-text indexes
./target/release/kc_cli index rebuild ./my-vault
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Rust (2021 edition) |
| Vault storage | SQLCipher (rusqlite + bundled) |
| Encryption | XChaCha20-Poly1305, Argon2id (objects); SQLCipher PBKDF2-HMAC-SHA512 (database); BLAKE3 hashing |
| Vector index | LanceDB + Apache Arrow |
| PDF parsing | pdfium-render |
| Identity | Ed25519 (ed25519-dalek), JWK/JWKS |
| CLI | clap 4 |
| Desktop | Tauri 2 + TypeScript frontend |

## License

MIT
