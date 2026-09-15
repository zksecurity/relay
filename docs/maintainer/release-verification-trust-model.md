# Final verification and release signing

Status: reviewed proposal only. This document does not describe implemented or
released behavior.

## Decision

The protocol requires the coordinator to run proof-tool's complete mathematical
replay before final approval. The final-parameter signer does not repeat that
expensive replay by default.

This preserves an existing coordinator requirement, not a new check: coordinator
finalization already called `replayAll` in proof-tool commit
[`c1f177e`](https://github.com/zksecurity/proof-tool/commit/c1f177ee486fd555fac0dc4d9812b86737fccdfd)
(July 31, 2026). PR #31 added the additional mandatory release-signer replay
on September 15. This proposal removes that duplicate requirement only for the
new format. The release-signer role itself remains required.

This deliberately adopts an **honest coordinator** assumption for final
cryptographic verification. A coordinator signature authenticates the
coordinator's statement; it cannot independently prove the replay happened.

We also trust the configured storage service to return committed state and
stored bytes according to its API. Independent freshness confirmations and
defenses against deliberate provider deception are outside this design.
Ordinary caching, timeout and interrupted-write handling remains required.

The MPC secrecy assumption remains separate: at least one participant must
honestly discard its contribution randomness.

Independent ceremony auditors remain optional. A positive audit minimum
requires their complete independent replays. A zero audit minimum means the
release has a coordinator-signed replay claim but makes no claim of independent
replay.

## Reuse the final-candidate checkpoint

Do not add a second coordinator verification record. The storage-first
`FinalCandidateRecorded` checkpoint already:

- is produced only after proof-tool replays both phases and reproduces the final
  parameters;
- binds the exact immutable checkpoint ancestry and closed replay inputs;
- binds the exact final candidate files by logical name, hash and size; and
- is signed by the coordinator only after proof-tool re-derives those facts.

In the new version, that checkpoint is the coordinator's replay statement. Its
transition explicitly records `verification_method: coordinator-full-replay`
and the actual approved proof-tool executable digest. The inventory is derived
from authenticated ancestry; the coordinator cannot supply a second ad hoc
input list.

It never relies on mutable `root.json`. A later frozen review checkpoint names
the exact final-candidate checkpoint record and signature.

## Normal GO sequence

```text
Coordinator authenticates the complete transcript
                         |
                         v
Proof-tool replays both phases and reproduces the final parameters
                         |
                         v
Coordinator signs FinalCandidateRecorded for those exact bytes
                         |
                         v
The review checkpoint freezes that checkpoint, evidence and final files
                         |
                         v
Final-parameter signer performs complete non-mathematical verification
                         |
                         v
Final-parameter signer signs those exact release files
                         |
                         v
GO may approve only that exact frozen release
```

Changing any bound byte requires another coordinator replay and a new
final-candidate checkpoint.

## Release-signer verification boundary

Proof-tool adds one named verification path for release signing. It traverses
the entire checkpoint ancestry and checks:

- the signed definition, identities and approved software;
- every checkpoint signature and legal state transition;
- every referenced artifact's logical name, hash and size;
- participant, cleanup, custody, closure and beacon signatures;
- the signed assurance policy and every required evidence count;
- the exact `FinalCandidateRecorded` replay statement; and
- agreement between the frozen inventory and files being signed.

It deliberately does **not** redo contribution mathematics or regenerate the
final parameters. For those expensive checks it relies on the coordinator's
signed final-candidate checkpoint under the honest-coordinator assumption.

This is not the existing fully replaying stored-checkpoint verifier with a
different label. Tests must prove that the release-signing verifier rejects
every non-mathematical tamper while never invoking the contribution-replay
callbacks.

## Independent replay

The public, policy-enforced way to claim independent replay is the existing
ceremony-auditor control. If its signed minimum is positive, GO requires the
specified number of passing independent replay records.

A release signer may voluntarily run the public replay command for personal
confidence. That does not create a second public assurance category. If the
ceremony wants to publish that assurance, the person must also be explicitly
assigned and enrolled as an auditor and submit the normal auditor record.

If a voluntary replay finds a mathematical mismatch, Relay must pause and
recommend investigation and NO-GO. It must not immediately offer “sign without
replay.” An interruption or resource failure is shown as incomplete rather than
a mathematical failure and may retry the exact inputs.

## NO-GO remains possible

A passing final-candidate checkpoint gates GO, not NO-GO.

If coordinator replay fails, is interrupted, or never produces a valid signed
final-candidate checkpoint, Relay can still create a terminal NO-GO decision.
That decision binds the exact immutable checkpoint record and signature
selected by the authenticated root, the attempted candidate digest when
available, and a non-sensitive failure or review reason. It does not claim a
passing replay and does not require a release manifest.

Likewise, a later independent replay mismatch can produce NO-GO bound to the
exact final-candidate checkpoint it rejected. Failed candidates remain private
except for the minimal signed rejection metadata.

## Failure and restart behavior

Final-candidate preparation and signing retain the guarded proof-tool flow:

1. authenticate the exact inputs and parent checkpoint;
2. complete the mathematical replay;
3. re-authenticate that the inputs and parent are unchanged;
4. load and match the coordinator key;
5. re-derive and sign the exact checkpoint; and
6. write the checkpoint and signature atomically.

Relay uploads immutable bytes before conditionally advancing `root.json`. A
crash can leave unreferenced bytes, but they do not indicate success. On
restart, Relay authenticates the current root:

- exact retained output with the same parent and candidate may be adopted;
- an already committed identical descendant is complete; and
- a changed parent, sibling checkpoint or candidate requires a new replay.

The review cannot freeze and GO cannot proceed until the authenticated
checkpoint chain contains the signed final-candidate checkpoint.

## Public wording

Relay, Tessera and release metadata state exactly what can be established:

- a valid coordinator-signed checkpoint states that full replay passed;
- accepted independent auditor replays: signed minimum and count; and
- external security reviews: signed minimum and count.

With zero independent audits, show:

> The coordinator signed the FinalCandidateRecorded checkpoint stating that
> full cryptographic replay passed. This ceremony assumes an honest
> coordinator. No independent full replay was required or claimed.

Do not call this independently verified or trustless. Upload success and a zero
exit status alone never become a replay claim. Recorded times establish signed
ordering claims, not external wall-clock proof.

## Versioning and compatibility

The proof-tool release that currently requires release-signer replay retains
that behavior for its schema. Do not silently change the meaning of its
released identifiers.

This proposal needs a new version of every signed boundary whose verification
meaning changes:

- storage-first definition/workflow identifier;
- final-candidate checkpoint transition;
- frozen review checkpoint;
- final ceremony transcript and inspection result; and
- Tessera setup contract and compatibility fixtures.

Keep the application-facing `proof-tool-key-manifest-v1` unchanged. Its existing
signed `setup_transcript_hash` binds the exact ceremony transcript. Add final
transcript V3 with the explicit release-verification policy and exact signed
coordinator final-candidate checkpoint references. Include that checkpoint pair
in the closed release inventory. No second release-authorization signature is
needed. Ordinary application key-bundle verification remains unchanged; the
coordinator replay claim requires complete ceremony verification.

Production decision V2 may retain its wire structure because it binds the exact
definition and release inventory. Its verifier must explicitly recognize
Definition V4 and require final transcript V3; it must never fall through to
legacy behavior. A new decision schema is needed only if its signed fields or
their meaning change independently of the already-bound ceremony version.

New-version GO verification fails closed without the exact signed
`FinalCandidateRecorded` replay statement. Old verifiers must reject the new
path, and new verifiers preserve the old path's mandatory release-signer replay.
Cross-version substitution must fail.

## Implementation boundary

Proof-tool owns mathematical replay, authenticated state validation and
cryptographic records. Relay owns Docker orchestration, S3/R2 locations,
uploads, conditional root updates and user guidance.

Relay may transport proof-tool's authenticated logical outputs. It may not
manufacture a passing replay statement, interpret command exit alone as one, or
teach proof-tool Relay-specific backend object keys.

## Required tests

- coordinator replay success and mathematical failure;
- interruption before signing and after atomic output;
- changed candidate, replay input, binary or parent before signing;
- stale parent, sibling checkpoint and conditional-root conflict;
- GO without the final-candidate replay statement;
- NO-GO without a passing statement or release manifest;
- complete non-mathematical release verification without math callbacks;
- tampered signature, hash, identity, policy, evidence, chronology or inventory;
- voluntary replay mismatch without a silent downgrade;
- legacy/new schema crossing in both directions; and
- Tessera displaying coordinator attestation without overstating it.

## Explicit trade-off

This removes duplicate expensive computation from the normal final-signer
journey. In exchange, when the signed audit minimum is zero, a dishonest or
compromised coordinator can sign a false replay claim. Signatures and hashes do
not remove that assumption.
