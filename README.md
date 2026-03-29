![Rust](https://img.shields.io/badge/Rust-2021-orange?logo=rust) ![Tauri](https://img.shields.io/badge/Tauri-2.x-blue?logo=tauri) ![License](https://img.shields.io/badge/license-MIT-green)

# KnowledgeCore

A local-first, encrypted knowledge vault for ingesting, indexing, and querying documents — available as both a CLI tool and a cross-platform desktop app. Documents are stored in an encrypted SQLite vault (SQLCipher), content-addressed with BLAKE3 hashes, and indexed with a vector store (LanceDB) for semantic retrieval. A trust and lineage layer tracks document provenance, authorship, and policy governance across devices.

## Tech Stack

| Layer | Technology |
|---|---|
| Core vault, encryption | Rust, SQLCipher (rusqlite + bundled), ChaCha20-Poly1305, Argon2, BLAKE3 |
| Document extraction | pdfium-render |
| Vector index | LanceDB + Apache Arrow |
| Identity & trust | Ed25519 (ed25519-dalek), JWK/JWKS providers |
| Recovery escrow | AWS KMS / Secrets Manager, Azure, GCP, HSM, local |
| CLI | clap 4 |
| Desktop app | Tauri 2, TypeScript frontend |
| Cloud sync | AWS S3 |

## Prerequisites

- Rust 1.77+ (2021 edition)
- Cargo
- Node.js 18+ and pnpm 10+ (for the desktop app only)
- Tauri CLI v2 (`cargo install tauri-cli --version "^2"`) (for the desktop app only)

## Getting Started

### CLI

```bash
# Build the CLI
cargo build --release -p kc_cli

# Initialize a new vault
./target/release/kc_cli vault init --vault-path ./my-vault --vault-slug my-vault

# Ingest documents from a folder
./target/release/kc_cli ingest scan-folder \
  --vault-path ./my-vault \
  --scan-root ~/Documents \
  --source-kind local

# Rebuild the semantic index
./target/release/kc_cli index rebuild --vault-path ./my-vault

# Query the vault
./target/release/kc_cli ask --vault-path ./my-vault "What are my notes on project X?"

# Sync to another vault or S3
./target/release/kc_cli sync push --vault-path ./my-vault --target-path s3://my-bucket/vault
```

### Desktop App

```bash
# Install JS dependencies
pnpm install

# Run in development mode
pnpm tauri dev

# Build for production
pnpm tauri build
```

### Run Tests

```bash
cargo test
```

## Project Structure

```
knowledgecore/
├── crates/
│   ├── kc_core/        # Vault, encryption, hashing, sync, trust, lineage, retrieval
│   ├── kc_extract/     # PDF and document text extraction
│   ├── kc_index/       # LanceDB vector index (build + query)
│   ├── kc_ask/         # Retrieval-augmented query service
│   └── kc_cli/         # CLI entry point (clap commands)
├── apps/
│   └── desktop/
│       ├── src-tauri/  # Tauri backend (Rust)
│       └── ui/         # TypeScript frontend
├── scripts/            # Dependency audit, size audit, cache cleanup
├── fixtures/           # Test corpus fixtures
└── plan/               # Design documents
```

<!-- TODO: Add screenshot -->

## Key Features

- **Encrypted vault** — SQLCipher-encrypted SQLite database with passphrase-based locking/unlocking
- **Content addressing** — Every document blob is BLAKE3-hashed for deduplication and integrity
- **Semantic search** — LanceDB vector index enables similarity-based document retrieval
- **Trust & identity** — Ed25519 device enrollment, JWKS identity providers, policy-based governance
- **Lineage tracking** — Document provenance graph with role-based locks and overlay annotations
- **Multi-provider recovery escrow** — Vault recovery keys distributed to AWS KMS, Azure, GCP, HSM, or local storage
- **Sync** — Push/pull with S3 and local paths; configurable merge policies

## License

MIT — see [LICENSE](LICENSE) for details.
