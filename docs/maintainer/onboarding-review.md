# Role onboarding: self-review and test scope

This is implementation self-review, not an independent security audit.

## Boundaries preserved

- Onboarding builds argument arrays for existing authenticated commands; it
  neither parses ceremony policy as authority nor implements signing.
- Key generation and final-parameter signing use prepared offline profiles.
  Opening them does not contact GitHub. The operator must disconnect the host.
- Witness/mirror online profiles and upload stations receive no key mount.
- Public imports use fixed destinations, explicit confirmation, and create-only
  writes. Importing is not signature verification. Trusted-key fingerprints need
  comparison through an independent channel.
- Profiles require the operator's identity ID where available. The initializer
  remains responsible for signed assignment/enrollment and tool checks.
- State is private and locked; release, role and directory changes stop resume.
  Child execution forwards termination and waits for cleanup.

## Issues corrected during review

- Keygen profiles could collide when several roles shared a ceremony alias.
  Their aliases now include the role and protected key directory.
- Online witness and mirror setup unnecessarily mounted keys; those mounts
  are omitted in the new onboarding path.
- The installer now creates a literal-quoted, executable start script, avoiding
  manual sourcing and shell-variable assembly. Older settings remain usable.
- Standard policy and both pinned Linux architectures are prepared automatically.
  Companion downloads require matching hashes and GitHub build provenance.
- New local tool records measure the actual tools without inventing a kit test
  or ceremony-mode approval. Host and container binary paths are separate.
- Environment setup distinguishes measured Docker checks, enforced execution
  controls, human precautions, and host/VM remnants that cannot be excluded.
- Separate role instances have distinct folders/profiles. Resume preserves the
  old release, keys and progress. Shared-lock errors identify the affected folder.
- Enrollment and observer receipt signing use a separate offline image. The
  owner reviews exact bytes; a reviewed hash catches changes before signing.
  Proof-tool checks the owner key and enrollment disclosure hash.
- The real contribution walkthrough caught indented environment JSON that
  proof-tool rejected. New plans use canonical bytes; earlier plans are preserved
  when a fresh canonical plan is needed. No existing profile is silently rewritten.
- Receipt exports get fresh directories carried into signing/upload prompts.
  Head selection authenticates local chains and rejects forks and known rollback.

## Tests and limitations

Unit tests cover required fields, saved IDs, role-specific key profiles, own-ID
binding in initialization commands, unchanged public imports, overwrite/symlink
rejection, release mismatch, and keyless transport profiles. Entry-point tests
execute the generated script from Bash and Zsh with metacharacters in paths.
An opt-in Docker test generates a real temporary identity with the offline
image, checks private-file permissions, then confirms reopening does not
regenerate it. Only temporary test keys are used.

The 2026-09-08 local Docker rerun passed in 650.52 seconds: three contributions
per phase, measured removal and signed cleanup, two real future Quicknet rounds,
public proof verification, two audits, operational evidence, final signing and
release verification. A wrong signer ID was rejected. The first attempt exposed
a macOS `/var` symlink in the test harness; physical temporary paths fixed it.
This used local Relay images, pinned released proof-tool bytes, same-host fixtures
and public-file handoffs—not full interactive onboarding, independent operators,
physical erasure, live cloud permissions or production performance.
Tests also cover invalid release receipts, modified/symlinked caches, cancelled
environment confirmation, host-path translation, fresh independent outputs and
explicit action approval. Opt-in tests download both pinned proof tools, verify
provenance, reuse the cache offline, and reject a changed native-tool hash.

The expanded menu-driven Docker lane generates identities, imports their public
files into an empty coordinator roster, initializes a tiny ceremony, signs and
verifies owner enrollments, checks resume, and creates both-phase participant,
observer, auditor and upload profiles. It runs a real disposable contribution using the guided
environment, confirms cleanup, accepts it, and prepares/signs witness and mirror
receipts. Software delivery uses explicit local compatibility evidence—not fake
published provenance. Storage uses non-network test configuration.

A separate full ceremony rerun passed in 650.84 seconds with the initial new
proof-tool commands. Authenticated discovery also passed against both completed
three-contribution phases. See [test instructions](onboarding-tests.md).
The expanded dialogue run passed in 19.69 seconds, including real PTY-based
witness/mirror launcher-to-Docker signing and fresh-signature checks. Linux
proof-tool command, ceremony, key-bundle, key-profile and prover tests passed.

Whole-transcript handoffs, cloud provisioning, real permissions, independent
operators and physical erasure are not established by these tests. Production
K=21 performance and GO/NO-GO approval are not claimed. The new published pairing
must be retested after proof-tool releases and Relay's pins are updated.
Local suggestions, observations and remembered files are not ceremony authority.
