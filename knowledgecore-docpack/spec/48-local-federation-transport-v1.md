# Local Federation Transport V1

Status: source contract; installed activation is separate.

## Ownership and purpose

KnowledgeCore remains the sole authority and storage owner for encrypted private documents, vault permissions, provenance, and logical document lifecycle events. This transport lets a local consumer request the existing lifecycle-aware V2 federation envelope without reading the vault, database, object store, or passphrase directly.

The transport is not a knowledge store, export, cache, index, scheduler, or background service. It runs in the foreground under an owner-started `kc_cli federation serve` process and binds exactly one vault to exactly one local Unix socket.

## Activation

```text
kc_cli federation serve <vault_path> \
  --socket-path <absolute_private_socket_path> \
  [--passphrase-env <owner_selected_environment_variable>]
```

The socket parent must already exist and must not be group- or world-writable. The server refuses an existing socket path instead of deleting it, sets the socket mode to `0600`, and removes only the same socket inode during an orderly shutdown. An encrypted vault can be unlocked inside the owner process from the named environment variable; the variable name and value are never part of the query protocol.

Starting, installing, supervising, scheduling, or publishing this process is outside this source contract.

## Request

One connection carries one JSON document and then closes its write half. The maximum request size is 64 KiB and the connection read/write timeout is five seconds.

```json
{
  "schema_version": "knowledgecore_federation_transport_request.v1",
  "session_id": "opaque-owner-session-id",
  "query": {
    "schema_version": "knowledgecore_federation_query_request.v2",
    "project_key": "owner/repository",
    "include_content": false,
    "limit": 20,
    "observed_at_ms": 0
  }
}
```

Unknown fields, unsupported versions, empty or oversized messages, and invalid session bindings fail closed. The request cannot contain a vault path, database handle, passphrase, subject, policy decision, lifecycle mutation, or fallback result.

`observed_at_ms` describes the composed query observation. It is not used as the authorization clock. KnowledgeCore validates authorization against its own process clock.

## Authorization

KnowledgeCore resolves the opaque session identifier to its owner-held identity record and verifies:

- the provider is enabled;
- the session is inside its validity window;
- the session has not been revoked;
- provider claim policy still permits it; and
- a bound lineage policy explicitly allows `document.federation.read` for the resolved subject and project key.

No matching allow is a denial. The caller cannot provide or override the subject. Authorization is evaluated through a read-only owner connection; the query does not apply migrations or write a second audit/canonical record.

## Response

A successful transport exchange uses `knowledgecore_federation_transport_response.v1` and contains either:

- `status: "ok"` with one unmodified `knowledgecore_federation_query_result.v2` owner envelope; or
- `status: "error"` with a bounded public code and message for protocol or pre-binding failures.

The serialized owner response is capped at 4 MiB. A larger result is replaced by a bounded transport error rather than streamed or truncated into a misleading partial owner envelope. Consumers may configure a lower cap and treat a rejected response as source unavailable.

Invalid, expired, revoked, or unbound identity sessions are represented as a V2 `permission_denied` source state with `participated: false`. Locked and corrupt owner sources retain the corresponding typed V2 states. These are partial/degraded evidence, never an empty successful answer.

The response must not contain the socket or vault path, passphrase, session identifier, raw subject, raw lifecycle reason, raw policy decision, or raw storage error. Lifecycle notices retain only owner hashes, event references, and authorization/reason digests already defined by V2.

## Failure and claim boundary

Missing sockets, timeouts, malformed or oversized responses, non-V2 results, and local I/O failures must be treated by consumers as source unavailable/error. Consumers must not reuse stale KnowledgeCore facts or infer deletion from absence.

Source tests can prove the broker/client contract and synthetic owner integration. They do not prove an installed broker, active unlock, configured Keychain item, Personal Ops daemon activation, scheduler state, deployment, or human use.
