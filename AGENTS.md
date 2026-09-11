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

## Cross-repository release sequence

When Relay depends on a proof-tool change, merge and release proof-tool first.
Wait for the exact protected-main `mpc-ci-FULL_COMMIT` release, verify both
architecture checksums and attestations, then update `release/role-images.json`
to those exact immutable assets. A merged proof-tool PR or local binary is not an
acceptable release pin.

Before merging Relay, update `release/release-notes.md`, run the normal Go,
shell, launcher, release, and ceremony checks, and report the exact PR head to
Tessera's compatibility workflow. Relay pull requests use a 12-second,
explicitly non-production witness window while still retrieving two real future
Quicknet rounds. Protected-main and daily scheduled checks use Tessera's
180-second rehearsal window. Production's 24-hour minimum is unchanged. Keep
the real end-to-end path through contributions, cleanup, both beacons, audit,
release signing, archive packing, and public replay; it detects incompatibilities
that isolated repository tests can miss.

After merge, wait for `role-images-FULL_COMMIT` and verify its human-readable
release notes, manifests, binaries, images, checksums, and protected-main
attestations. Relay publication alone does not activate the release in Tessera.
Tessera must retain it in the compatibility matrix, pass the exact-tag published
release readiness workflow, provision each deployment's private catalogue, and
explicitly select the default. Existing selected and frozen ceremonies remain
pinned to their original release.

The released one-observer policy uses `contracts/setupv2r2/` and ruleset
`two-phase-v2` version 2. Preserve `contracts/setupv2/` unchanged for old
ceremonies. Any future rule change needs another versioned contract and a
matching proof-tool, Relay, Tessera, and deployment release sequence.
