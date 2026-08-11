# GA Artifact Manifest v0.1.0 (macOS-first)

## Milestone
- C2 — macOS GA Artifact Packaging (Signed + Notarized)

## Candidate Commit Context
- Branch: `codex/closeout-c2-macos-artifacts`
- Product version: `0.1.0`
- Bundle identifier: `com.knowledgecore.desktop`

## Commands Executed
All command forms below are sourced from:
- `~/Projects/knowledgecore/knowledgecore-docpack/AGENTS.md`
- `~/Projects/knowledgecore/knowledgecore-docpack/docs/04-post-dk-ops-and-followup-policy.md`
- `~/Projects/knowledgecore/knowledgecore-docpack/CHECKLIST_VERIFICATION.md`

### Desktop gate rerun (C2 required)
- Command: `pnpm lint && pnpm test && pnpm tauri build`
- START_UTC: `2026-02-15T07:11:39Z`
- END_UTC: `2026-02-15T07:12:16Z`
- Result: `PASS`

### Recovery fix applied
- File updated: `~/Projects/knowledgecore/apps/desktop/src-tauri/tauri.conf.json`
- Change: set `"bundle.active": true` so canonical `pnpm tauri build` emits distributable bundles.

### Artifact generation
- Command: `pnpm tauri build` (after recovery fix)
- Result: `PASS`
- Bundles produced:
  - `~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore Desktop.app`
  - `~/Projects/knowledgecore/target/release/bundle/dmg/KnowledgeCore Desktop_0.1.0_aarch64.dmg`

## Artifact Inventory
1. `~/Projects/knowledgecore/target/release/apps_desktop_tauri`
- Type: release executable (arm64)
- Size bytes: `37054112`
- SHA-256: `20d7db3f48a7780d87bd7c5b5b02b067314408db023551597810d54b5c6a63b4`

2. `~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore Desktop.app`
- Type: macOS application bundle
- Main executable path: `~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore Desktop.app/Contents/MacOS/apps_desktop_tauri`
- Main executable size bytes: `37054112`
- Main executable SHA-256: `20d7db3f48a7780d87bd7c5b5b02b067314408db023551597810d54b5c6a63b4`

3. `~/Projects/knowledgecore/target/release/bundle/dmg/KnowledgeCore Desktop_0.1.0_aarch64.dmg`
- Type: macOS disk image
- Size bytes: `14363929`
- SHA-256: `1c38d16d8317db82f620510e5d016386e3376d28e56688e6ba279377c9b28067`

## Signing and Notarization Evidence

### Local signing identity check
- Command: `security find-identity -v -p codesigning`
- Result: `0 valid identities found`

### App signature state
- Command: `codesign -dv --verbose=4 ~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore Desktop.app`
- Result summary:
  - `Signature=adhoc`
  - `TeamIdentifier=not set`

### Signature verification check
- Command: `codesign --verify --deep --strict --verbose=2 ~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore Desktop.app`
- Result: `FAIL`
- Error:
  - `code has no resources but signature indicates they must be present`

### Gatekeeper assess check
- Command: `spctl --assess --type execute --verbose=4 ~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore Desktop.app`
- Result: `FAIL`

### Notary profile readiness check
- Command: `xcrun notarytool history --keychain-profile knowledgecore-ga`
- Result: `FAIL (EXIT_CODE=69)`
- Error:
  - `No Keychain password item found for profile: knowledgecore-ga`

### Stapler verification check
- Command: `xcrun stapler validate ~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore Desktop.app`
- Result: `FAIL`
- Message:
  - `does not have a ticket stapled to it`

## Distribution Verification Instructions
1. Verify checksums before publication:
- `shasum -a 256 ~/Projects/knowledgecore/target/release/bundle/dmg/KnowledgeCore\ Desktop_0.1.0_aarch64.dmg`

2. Verify signature status:
- `codesign --verify --deep --strict --verbose=2 ~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore\ Desktop.app`

3. Verify notarization ticket:
- `xcrun stapler validate ~/Projects/knowledgecore/target/release/bundle/macos/KnowledgeCore\ Desktop.app`

## C2 Stop/Go Decision
- Decision: `STOP (NO-GO)`
- Blocking conditions hit:
  1. Signing identity unavailable.
  2. Notary keychain profile missing.
  3. App is not notarized/stapled.

## Required Recovery Actions (must complete before C2 close)
1. Install/import a valid Apple Developer ID Application signing certificate into keychain used by the build host.
2. Configure notarization credentials profile:
- `xcrun notarytool store-credentials <profile> --apple-id <id> --team-id <team> --password <app-specific-password>`
3. Re-sign app bundle with Developer ID identity.
4. Submit and pass notarization, then staple ticket to distributed artifacts.
5. Re-run signature/notarization verification commands and update this manifest with successful evidence.

## C2 Completion Status
- Milestone status: `IN PROGRESS (blocked by credentials)`
- Close criteria not yet met: signed + notarized + stapled artifacts.
