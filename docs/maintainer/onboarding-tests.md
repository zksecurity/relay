# Testing guided onboarding

Run ordinary checks first: `go test ./...`, `go test -tags relaylocal ./...`,
and `go vet ./...`. Proof-tool's ceremony suites need Linux for executable-
identity checks; run `go test ./cmd/mpc-ceremony ./internal/mpcceremony` there.

## Real Docker dialogues

Build matching local online/offline images and a native Relay launcher from
the changed sources. Use immutable image IDs. This is local development
evidence, not release provenance; never change release pins to invented assets.

Run `scripts/verify-ceremony-kit-compatibility.sh` with the exact image binaries
and hashes in Linux. Retain its successful `compatibility.json`. This performs
a real tiny contribution and acceptance, not just a version check.

Set these variables in the test terminal:

- `RELAY_FLOW_DOCKER=1`
- `RELAY_ROLE_ONLINE_IMAGE` and `RELAY_ROLE_OFFLINE_IMAGE`: immutable local images
- `RELAY_ROLE_PLATFORM`: `linux/amd64` or `linux/arm64`
- `RELAY_TEST_COMPATIBILITY`: absolute path to the real compatibility evidence
- `RELAY_NATIVE_TEST_BINARY`: absolute path to the freshly built native launcher
- `RELAY_TEST_PROOF_BINARY`: cached Linux proof-tool binary matching the images

With `expect` installed, run:

```bash
go test ./cmd/relay -run '^TestAllRoleInteractiveDockerOnboarding$' -count=1 -v -timeout 10m
```

This uses temporary role folders and real Docker cryptography. The observer
terminal subtests use a PTY and the actual native launcher, including its nested
Docker confirmations. Set `RELAY_DIALOGUE_TRACE=1` for full public prompt logs.
Never use production keys, credentials or a live ceremony folder.

## Full ceremony and discovery

For `TestRoleFlowDockerFullCeremony`, additionally set `RELAY_PROOF_TOOL_DIR` to
the matching source and `RELAY_FLOW_WORK` to a fresh dedicated test directory.
Allow 30 minutes; two real future Quicknet rounds require waiting. This lane
uses same-host operational fixtures and public-file handoff, not live cloud.

Afterward, set `RELAY_HEAD_TEST_WORK` to that completed test work directory and
run `TestDockerAuthenticatedHeadDiscovery`. It verifies both latest local heads
and saved checkpoints without modifying the transcript. Unit tests separately
reject forks, same-position conflicts and known rollback.

## Release order

Merge/release proof-tool first. Verify its published architectures/provenance,
update Relay's `release/role-images.json`, and rerun the released pairing before
merging/releasing Relay. The new guide needs `ops prepare-enrollment` and
`ops sign`; an older proof-tool release cannot run those steps.
