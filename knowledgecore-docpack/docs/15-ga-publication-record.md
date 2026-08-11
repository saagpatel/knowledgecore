# Publication Record (Pilot Track)

## Publication Metadata
- Publication timestamp (UTC): `2026-02-15T07:21:32Z`
- Milestone: `C5 — Release Execution (Pilot variant)`
- Release class: `Internal Pilot`
- GA status: `Deferred`

## Tag and Commit
- Tag: `v0.1.0-pilot.1`
- Commit SHA: `dfbec2a8aacdb237a369c80a3ad2fb0f6aa35085`
- Tag annotation: `Pilot release v0.1.0-pilot.1 (GA deferred)`

## Artifact Publication Channel
- Channel type: local internal release channel
- Location:
  - `~/.knowledgecore-release-channel/pilot/v0.1.0-pilot.1`
- Published artifact(s):
  - `~/.knowledgecore-release-channel/pilot/v0.1.0-pilot.1/KnowledgeCore Desktop_0.1.0_aarch64.dmg`
  - `~/.knowledgecore-release-channel/pilot/v0.1.0-pilot.1/SHA256SUMS.txt`

## Source Artifact Traceability
- Build source artifact:
  - `~/Projects/knowledgecore/target/release/bundle/dmg/KnowledgeCore Desktop_0.1.0_aarch64.dmg`
- Build SHA-256:
  - `93a1dfc289fd271bb04933f3dd85726f4dc57f3d178980cdd7c930acfe704fc3`

## Published Checksum Manifest
- `SHA256SUMS.txt` contents validate:
  - `KnowledgeCore Desktop_0.1.0_aarch64.dmg` => `93a1dfc289fd271bb04933f3dd85726f4dc57f3d178980cdd7c930acfe704fc3`

## Post-Publish Integrity Verification
- Verification command:
  - `(cd ~/.knowledgecore-release-channel/pilot/v0.1.0-pilot.1 && shasum -a 256 -c SHA256SUMS.txt)`
- Result: `PASS`

## Release Notes Source
- `~/Projects/knowledgecore/knowledgecore-docpack/docs/11-ga-release-notes-v0.1.0.md`

## Trust Posture Disclosure
- This publication does not satisfy GA trust requirements because Developer ID signing and notarization remain unavailable.
- Blocking evidence is documented in:
  - `~/Projects/knowledgecore/knowledgecore-docpack/docs/10-ga-artifact-manifest-v0.1.0.md`

## Distribution Policy
- Approved for internal pilot audience only.
- Not approved for public GA distribution.
