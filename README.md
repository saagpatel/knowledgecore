# KnowledgeCore

[![Rust](https://img.shields.io/badge/Rust-dea584?style=flat-square&logo=rust)](#) [![License](https://img.shields.io/badge/license-MIT-blue?style=flat-square)](#)

> Your documents, encrypted and semantically searchable — no cloud, no accounts, no compromise.

KnowledgeCore is a local-first, encrypted knowledge vault for ingesting, indexing, and querying documents. Documents are stored in an encrypted SQLite vault (SQLCipher), content-addressed with BLAKE3 hashes, and indexed with LanceDB for semantic retrieval. A trust and lineage layer tracks document provenance, authorship, and policy governance across devices.

## Features

- **Encrypted vault** — SQLCipher-backed storage with Argon2 key derivation and ChaCha20-Poly1305 encryption
- **Semantic search** — LanceDB vector index with Apache Arrow for fast similarity queries
- **Content addressing** — BLAKE3 hashes ensure integrity and deduplication
- **PDF extraction** — pdfium-render for high-fidelity document parsing
- **CLI + desktop** — full-featured `kc_cli` plus a Tauri 2 desktop app covering the same workflow
- **Recovery escrow** — pluggable escrow backends: AWS KMS, Azure, GCP, HSM, or local

## Quick Start

### Prerequisites
- Rust 1.77+ (2021 edition)
- Cargo
- Node.js 18+ and pnpm (desktop app only)

### Installation
```bash
cargo build --release -p kc_cli
```

### Usage
```bash
# Initialize a new vault
./target/release/kc_cli vault init --vault-path ./my-vault --vault-slug my-vault

# Ingest documents
./target/release/kc_cli ingest scan-folder \
  --vault-path ./my-vault --scan-root ~/Documents --source-kind local

# Rebuild the semantic index
./target/release/kc_cli index rebuild --vault-path ./my-vault
```

## Tech Stack

| Layer | Technology |
|-------|------------|
| Language | Rust (2021 edition) |
| Vault storage | SQLCipher (rusqlite + bundled) |
| Encryption | ChaCha20-Poly1305, Argon2, BLAKE3 |
| Vector index | LanceDB + Apache Arrow |
| PDF parsing | pdfium-render |
| Identity | Ed25519 (ed25519-dalek), JWK/JWKS |
| CLI | clap 4 |
| Desktop | Tauri 2 + TypeScript frontend |

## License

MIT
