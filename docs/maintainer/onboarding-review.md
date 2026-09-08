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

## Tests and limitations

Unit tests cover required fields, saved IDs, role-specific key profiles, own-ID
binding in initialization commands, unchanged public imports, overwrite/symlink
rejection, release mismatch, and keyless transport profiles. Entry-point tests
execute the generated script from Bash and Zsh with metacharacters in paths.
An opt-in Docker test generates a real temporary identity with the offline
image, checks private-file permissions, then confirms reopening does not
regenerate it. Only temporary test keys are used.

The earlier complete tiny ceremony result is recorded in
[workflow review](role-workflow-review.md); it is not a new end-to-end test of
onboarding or released-image provenance.
Matching tool receipts, environment statements, enrollment authoring/signing,
raw offline receipt signing, whole transcript handoffs and cloud provisioning
remain external preparation. No receipt, observation or consent is fabricated.
The helper cannot promise a command-free process for those external tools yet.
