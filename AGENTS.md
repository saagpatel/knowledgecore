<!-- portfolio-context:start -->
# Portfolio Context

## What This Project Is

KnowledgeCore is a local-first knowledge vault with opt-in encryption for ingesting, indexing, and querying documents without cloud accounts. It supports SQLCipher database encryption, content-addresses documents with BLAKE3, builds LanceDB vector indexes using deterministic byte-histogram embeddings, parses PDFs with pdfium, and exposes both a Rust CLI and a Tauri desktop workflow.

## Current State

The README describes a privacy/security-heavy document system with encrypted storage, semantic search, document provenance, policy governance, and recovery escrow options.

## Stack

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

## How To Run

```bash
# Initialize a new vault
./target/release/kc_cli vault init ./my-vault my-vault

# Ingest documents
./target/release/kc_cli ingest scan-folder \
  ./my-vault ./fixtures/golden_corpus/v1 local

# Rebuild the vector and full-text indexes
./target/release/kc_cli index rebuild ./my-vault
```

## Known Risks

- Treat vault encryption and key derivation as high-risk surfaces; do not weaken SQLCipher, Argon2, ChaCha20-Poly1305, or BLAKE3 flows casually.
- Keep indexing/search local-first and avoid adding cloud sync unless an explicit design/approval path exists.
- CLI and desktop workflows should stay aligned around the same vault model and provenance semantics.

## Next Recommended Move

Use this context plus the README and supporting docs to resume the next active task, then promote the repo beyond minimum-viable by capturing a dedicated handoff, roadmap, or discovery artifact.

<!-- portfolio-context:end -->
