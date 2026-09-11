# Relay CLI development

This is `zksecurity/relay`, the local ceremony CLI. The companion Tessera website
is a separate repository, `zksecurity/tessera`; keep website changes there.
Inspect Git status and preserve unrelated changes and local ceremony state.
New explicit user instructions supersede this guidance.

## Tessera integration

Read `docs/tessera-setup-v2.md` and `contracts/setupv2/README.md` before changing
the shared setup flow. The schema, ruleset, approved beacon profile, canonicalization
implementation, and shared fixtures in `contracts/setupv2/` define the contract.
Tessera vendors these files byte-for-byte with a source commit/hash lock; coordinate
contract changes with its sync script and cross-repository tests.

- The website calls the tool **CLI**. Preserve the actual `relay` executable,
  command names, and repository references in technical instructions.
- Preserve every public input field and append only `result` when completing a
  setup. Do not silently remap identities or alter a downloaded plan.
- Website account bindings, people, ownership, and reviews are not CLI transport
  data. Private keys, credentials, and local paths stay out of public setup files.
- Opening a completed setup is verification/review-only; never initialize or sign
  again. Preserve interrupted initialization and existing recovery restrictions.
  Never automatically overwrite local work to resolve an input mismatch.
- Enforce strict parsing, shared limits, approved profiles, and exact hash domains
  from the contract. Hash signed artifacts as exact bytes; do not reserialize them.
- Website coordinator-assigned access does not prove signing-key possession and
  does not remove protocol enrollment or contribution signatures. Frozen signing
  identity replacement requires a future compatible protocol path, not a website
  override. Preserve legacy command and frozen setup compatibility.

Integration code is in `cmd/relay/tessera_v2.go`, `tessera_prepare.go`, and
`coordinator_prepare.go`. Keep docs and guided menu labels consistent with the
actual commands; inspect current menu numbering before inserting actions.

## Validation and releases

Run `go test ./...` and `go vet ./...` for Go changes, plus applicable formatting,
shell, and release checks required by CI. Contract changes also require shared
Go/JavaScript vectors and the real signed round trip with Tessera. Optional tests
skipped for missing tools/fixtures are not passing evidence. Use a proof-tool
verified against current `release/role-images.json` checksum and attestation pins,
not an arbitrary cached binary or older source checkout.

Retain dependency inventory, SBOM, and reproducibility checks. Dependency changes
may require updating `scripts/relay-release-tool/main.go` as well as `go.mod` and
`go.sum`. Build release artifacts from a clean checkout into an external output
directory. Do not weaken release checks to make CI pass.

Do not commit private keys, grants, credentials, local ceremony state, or build
outputs. Required generated source and deliberately public test fixtures belong
in Git; confirm fixtures contain no secrets. Synthetic release metadata remains
test-only even when the fixture's signatures are real.

Published availability requires the compatible protected-main release workflow,
including its attested manifest; passing PR tests alone is insufficient. Respect
required reviews and do not bypass release protections. Website activation also
requires its separate trusted-release provisioning and deployment smoke check.
Every PR must update `release/release-notes.md` with a short human-readable summary
and an explicit Tessera compatibility statement; the protected-main release uses
that reviewed text instead of a generated commit list.
For documentation-only edits, verify referenced paths and content; a full test
run is unnecessary.

The private Tessera repository runs the website/CLI integration matrix. Before
merging a CLI PR, a maintainer runs its `scripts/check-relay-pr.mjs PR_NUMBER`
against the reviewed exact head. The required public status is `Tessera integration`;
a new commit needs a new run. Keep private source and logs in Tessera. Changes to
the setup schema/rules/beacon require a new versioned contract directory while
retaining existing versions and their signed compatibility fixtures.

The unreleased one-observer policy uses `contracts/setupv2r2/` and ruleset
`two-phase-v2` version 2. Preserve `contracts/setupv2/` unchanged for old ceremonies.
Do not activate revision 2 until the matching proof-tool and CLI releases exist.
