CREATE TABLE IF NOT EXISTS sync_signing_keys (
  device_id TEXT PRIMARY KEY,
  public_key TEXT NOT NULL,
  signature_alg TEXT NOT NULL,
  seed_ciphertext TEXT NOT NULL,
  seed_nonce TEXT NOT NULL,
  kdf_alg TEXT NOT NULL,
  kdf_salt_id TEXT NOT NULL,
  key_reference TEXT NOT NULL,
  created_at_ms INTEGER NOT NULL,
  rotated_at_ms INTEGER,
  deleted_at_ms INTEGER,
  FOREIGN KEY(device_id) REFERENCES trusted_devices(device_id)
);

CREATE INDEX IF NOT EXISTS idx_sync_signing_keys_active
  ON sync_signing_keys(deleted_at_ms, created_at_ms);
