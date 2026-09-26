# Guided V5 production decision

Status: decision questionnaire, decision-signature AWS handoff, and the earlier
release-review snapshot/package handoff are implemented in the draft Relay
worktree. Full two-host AWS and Linux ceremony qualification remains pending
before release. The change affects the
coordinator and release-signer guides. It does not change the pinned proof-tool,
the signed ceremony definition, or an existing prepared decision. The AWS
handoff is transport, not a new approval or a substitute for signature checks.

## Exact upgrade qualification before production use

Before release, run a test-only one-machine smoke check of the candidate's
actual `start.sh` menus with a small circuit and separate role directories.
Because an unpublished PR has no attested role-images release, label any local
release fixture synthetic and do not count its release verification as passed.
A small K11 circuit can exercise V5's circuit-bound GO format with two
participants per phase. This synthetic smoke uses test-only role images and
review answers, so a prepared GO from it is not production approval. Supplement
the menu run with direct unit and fake-AWS tests, but do not substitute those
for the menu run.

Before release, also run the candidate's two-host AWS handoff using the actual
coordinator and signer `start.sh` menus. Identify any test-only release fixture
and do not count it as attested release verification. Exercise a signed release,
guided decision, private AWS packet,
separate temporary download and upload grants, offline signer review and
signing, public signature return, required-signature verification, and archive
packing. Test refusal during an unfinished operation, an expired grant renewed
without another signature, and a wrong account, bucket, or credential binding.
Independently verify the final archive against the known ceremony ID and
coordinator key. The two hosts must each follow their actual `start.sh` menus;
direct commands are supplemental diagnostics. This candidate test does not
qualify an upgrade or the published pair.

After v0.6.3 is published with its manifest and attestations, run a fresh
isolated two-host V5 ceremony with the exact published v0.6.0 launchers and
approved images. Complete Phase 2, save both guides at an operation boundary,
then upgrade the coordinator and signer separately to the exact published
v0.6.3 launchers. Confirm that the signed definition, proof-tool image pin,
identities, and completed checkpoints are unchanged. Repeat the decision and
AWS handoff through both `start.sh` menus, then independently verify the final
archive. Record both release commits, architecture-specific hashes, image pins,
ceremony ID, test storage destination, upgrade boundary, results, and verifier
report. Only that run qualifies the exact published pair for an ongoing
production ceremony.

For the retained pointer-based `G` action, the coordinator's host uses its
reviewed AWS login binding, including renewal of temporary session credentials.
Before asking for `PUBLISH APPROVED GO`, Relay starts and aborts a multipart
upload at both the exact archive key and exact pointer key. This probes upload
permission without publishing an object. It cannot guarantee later network
availability or public readback; those remain checked after publication.

Scope of the first implementation: signed V5 policies with zero optional
ceremony audits, external security-audit signoffs, public witnesses, and
mirrors. This covers the ceremony used to qualify the guided flow. Relay
checks the signed policy before asking questions and directs other policies
to the existing reviewed manual V5 draft path. Supporting nonzero optional
requirements needs a separate implementation that reads the actual signed
package evidence and signoffs; the questionnaire must never manufacture
them. Pinned V5 also caps each gate at 32 evidence references, so 17–20
external signoffs require a proof-tool change even for the manual path.

## Decision

Restore the coordinator questionnaire in `start.sh`. Relay collects attributable
answers about work that actually happened, generates the V5 draft and required
review reports, displays the complete result, and calls the pinned proof-tool
to prepare it. Nobody must write JSON or Markdown by hand for the human-review
gates. The coordinator and release signer review the exact generated decision
and reports before signing. Their signatures approve those claims; proof-tool
cannot determine whether the human statements are true.

The questionnaire does not weaken V5, invent an absent review, or turn file
presence into `PASS`. Structured `No`, `Unknown`, unfinished-review, rejected
conclusion, failed rehearsal, and unresolved-blocker answers map to `FAIL` or
`PENDING` and therefore to NO-GO. Relay cannot reliably classify adverse facts
buried in prose; both signers must read the displayed findings and refuse a
contradictory GO. Required signed audits
and package evidence still come from the ceremony, never from answers. The
existing manual V5 draft/evidence path remains available for recovery.

## What V5 requires

Relay reads the ceremony ID, circuit binding, source commit, assurance policy,
final-release checkpoint, candidate ID, and required decision signers from
authenticated records. The decision and every reference must bind those exact
values. Relay never asks the operator to type a known hash or identifier.

The V5 decision contains all 13 gates in proof-tool's fixed order:

| Gate | Source of result |
| --- | --- |
| Source release | Relay-generated report of the coordinator's attributed source-review answers, at canonical `decision/evidence/source-release.json`. |
| Signed final release | Verified release package; no extra review file. |
| Operational evidence | Verified release package; no extra review file. |
| Independent ceremony audits | Signed policy and verified package audits; `NOT_REQUIRED` only when policy requires zero. |
| External security audits | Signed policy and required signed reports; `NOT_REQUIRED` only when policy requires zero. |
| Exact-circuit rehearsal | Relay-generated report of the rehearsal review, bound to the exact signed circuit. |
| Mainnet deployment plan | Relay-generated plan from the coordinator's specific answers. |
| Formal GO/NO-GO checklist | Relay-generated Markdown gate summary with `.md` logical name. |
| Participant host security | One bounded aggregate report with an attributed entry for every accepted contribution. |
| Participant randomness | One bounded aggregate report with an attributed entry for every accepted contribution. |
| Participant cleanup | One bounded aggregate report with an attributed entry for every accepted contribution. |
| Public witnessing | Signed policy and verified package evidence; `NOT_REQUIRED` only when policy requires zero. |
| Independent mirrors | Signed policy and verified package evidence; `NOT_REQUIRED` only when policy requires zero. |

Relay maps the structured answers to `PASS`, `FAIL`, or `PENDING` for human
gates, then generates exact evidence references and the canonical V5 draft.
The mapping is fixed and tested; it never guesses a positive outcome from
free text or file presence. A `PASS` needs an affirmative reviewed conclusion
and concrete findings. `FAIL` or `PENDING` yields NO-GO, never GO with a
warning. Only the four policy-defined optional gates may be `NOT_REQUIRED`.

Proof-tool checks format, binding, hashes, file integrity, policy-derived
gates, and signatures. It does not determine whether the human prose is true
or a review was sufficient. Both signers must read the reports and decide
whether to sign. Relay labels package checks as verified and questionnaire
answers as attributed human claims. The coordinator checks that the generated
reports faithfully record the answers and honestly describe the underlying
work. The release signer reads the same reports and decides whether they
support the stated gates. Neither signer must author the report files.
Relay preflights the generated reports and draft against their individual
16 MiB V5 size limits. Pinned proof-tool enforces the canonical decision's
16 MiB limit during preparation; per-report checks alone are insufficient.

## First release: coordinator `start.sh` path

The coordinator starts from a verified signed final release. The menu keeps
the existing decision numbering:

```text
1) Answer review questions and prepare the decision
2) Review the exact decision and sign mine
3) Verify required signatures and pack the archive
4) Send the decision packet through AWS
5) Fetch the release signer's public signature from AWS
6) Issue or renew a temporary private signer transfer grant
0) Back
```

1. `D → 1` shows the authenticated ceremony, final release, circuit, source
   commit, signed policy, and required signers. It asks the review questions
   below, without making anyone retype values Relay already verified. Each
   answer can be saved and resumed before preparation. Relay shows the full
   answers, derived gates, adverse findings, and generated files. After the
   coordinator confirms `PREPARE DECISION`, Relay generates the reports and
   V5 draft, verifies every file hash and binding, and calls pinned
   `mpc-ceremony decision prepare`. Preparation creates no signature. A
   **Prepare my existing V5 draft** choice retains the manual recovery path.
2. `D → 2` presents the canonical prepared decision, its SHA-256, all gate
   assessments, the evidence inventory, and a clear distinction between
   proof-tool checks and human claims. The coordinator opens or exports the
   exact files for reading, then personally enters `SIGN DECISION`. Relay uses
   the existing V5 `decision sign` verification before using the key. No
   second questionnaire is added at signing. A signer who disagrees with an
   answer or assessment stops; Relay does not revise a prepared decision in
   place.
3. `D → 4` prepares a decision handoff containing the authenticated
   post-release public snapshot inventory and root, canonical decision,
   referenced evidence, and a bounded byte-exact transport manifest outside
   the canonical decision tree. The signed snapshot's potentially large
   content-addressed objects already reside in the configured published
   bucket and are referenced rather than uploaded twice. The coordinator
   uploads the decision and referenced evidence as individual
   content-addressed objects to a private handoff prefix in the configured
   AWS inbox bucket, checks each readback, and publishes the completion
   manifest last with create-only semantics. Relay bounds aggregate
   download size; disk exhaustion stops the transfer without promoting an
   incomplete packet. Each referenced snapshot download retains
   its existing 16 GiB bound. Relay displays the
   ceremony ID, final checkpoint, decision digest, manifest key and digest.
   A retry accepts only identical complete bytes. The packet stays private
   before GO and does not become an official public release.
4. `D → 6` issues a short-lived AWS STS grant through the coordinator's
   configured grant-role issuer after the packet is complete. The coordinator
   chooses a **download grant** before signer review or a distinct **upload
   grant** after offline signing. The download session policy permits
   `GetObject`/`GetObjectVersion` only for the exact manifest key and the
   decision's `objects/*` prefix. The downloaded manifest still lists and
   hashes every allowed object. The upload policy permits `PutObject`,
   `GetObject`, and `GetObjectVersion` only for this signer's exact public
   signature key. Neither policy grants list, delete, published-bucket,
   neighboring-prefix, or other-decision access. AWS IAM cannot require
   Relay's create-only upload header; a leaked upload grant can preempt the
   exact key and cause a visible denial of service, but cannot create a valid
   decision signature. The private mode-0600 grant binds the ceremony, candidate, final checkpoint, decision,
   manifest digest, signer identity, destination, and expiry. Relay saves it
   outside the coordinator's mounted work folder and public tree, then prints
   its path; the coordinator delivers that
   private file to the signer through an agreed confidential channel. The
   signer stores it outside the mounted work, key, and trust folders; Relay
   rejects a grant inside any of those folders or under symbolic-link
   directories. The
   grant is not uploaded to AWS or embedded in the public packet. A renewed
   grant is a new file and STS session for the same immutable handoff; it never
   changes or repeats the decision signature. Relay explains that earlier
   sessions may remain valid until expiry.
5. On the release signer's **online, keyless** `start.sh` handoff screen,
   separate from the offline signer guide, the signer selects **Download
   decision packet from AWS**. The coordinator privately delivers the grant
   file and separately communicates the ceremony ID, final-checkpoint digest,
   decision digest, and manifest digest for comparison. These transport hints
   are not trust anchors. The signed ceremony does not contain an AWS bucket
   or origin. Relay validates the grant's bucket and fixed key shape, checks
   the downloaded packet against the grant's exact bindings, and displays
   those bindings for comparison. It never selects a "latest" packet from an
   AWS listing. The signer selects the private download grant file, whose
   expiry Relay checks before using its temporary credentials. It
   downloads the snapshot objects from the published origin and decision
   objects from the private handoff into a fresh directory with strict
   per-file and total limits, and checks the manifest and every object hash.
   If this exact local download is already complete, the signer guide
   rechecks its retained bytes and reuses it without another AWS grant. If
   the retained snapshot is missing or damaged, a new grant for the same
   immutable packet permits a fresh download; only after all bytes check
   does Relay replace the private transport path. A conflicting partial file
   already in the canonical decision tree stops this retry and requires
   reviewed manual recovery; Relay never replaces it automatically. The
   earlier files remain available for review.
   The offline guide then authenticates the signed snapshot through the
   existing path and verifies the exact decision and evidence with the pinned
   proof-tool. The previously authenticated coordinator key and ceremony ID
   remain the signer's trust anchors. A downloaded packet
   is not evidence of current freshness; the UI shows its signed update and
   decision digest. The signer reads every generated report and compares its
   claims and adverse findings with the gate results. They then disconnect
   all networks and use the existing offline `D → 2` review and
   `SIGN DECISION` step. No AWS credentials or network are mounted in the
   signing container.
6. After offline signing, the signer exits the signing guide, reconnects,
   and chooses **Upload my public decision signature** in the keyless
   `start.sh` handoff. They select a newly issued private upload grant for the
   identical packet. If it expires, the coordinator issues another upload
   grant; the existing signed public signature is retained and never regenerated
   by the transfer action. No AWS
   profile is required on the signer host. The online action reads only the public
   signature and authenticated public metadata; it cannot launch the signer
   container or open `signing.hex`. Relay uploads the exact public
   `release-signer.sig` under a ceremony, release, decision digest, and signer
   ID-bound immutable key and reads back its size/hash. The temporary grant is
   a transport prerequisite, not a decision signer; without it, the manual
   public-file return remains an explicit fallback. The coordinator's
   **Fetch decision signature from AWS** action downloads only that expected
   key with a strict size bound into a fresh path, records its hash, and
   retains it in the canonical decision tree without replacing a
   different file. `D → 3` then checks the cryptographic signer/decision
   binding and complete V5 threshold with pinned proof-tool; fetch alone
   never reports the decision verified.
   A missing, partial, duplicate, or mismatched object never counts as an
   approval. If the coordinator signs NO-GO, V5 permits its one authorized
   signature; signer countersignature is optional.
7. `D → 3` checks the authenticated returned public signature and builds a staged archive
   from the canonical release and decision tree, enforcing the archive
   allowlist and manifest. Relay records the staged archive's hash and size
   before extraction. It extracts that archive into a private
   verification tree, checks the extracted inventory against the manifest,
   and calls pinned proof-tool `decision verify` once against those exact
   extracted bytes. For GO it checks the full required signer set; for NO-GO
   it checks V5's requirement for at least one authorized signature and Relay
   separately requires that signature to be the coordinator's for this guided
   path. It rechecks the
   extracted inventory, and compares the staged archive's hash and size with
   the pre-extraction values. Before retaining the archive without replacement
   it compares them again; any change stops packing and requires fresh
   verification. It never verifies one mutable tree and publishes another.
   For this ceremony's zero-auditor policy, GO needs the coordinator and
   release signer; V5 also requires every package auditor if a policy has
   them. A signed NO-GO may be packed as a clearly labeled evidence archive
   even if another signer withholds approval. The guided coordinator path
   requires the coordinator's signature for either outcome; V5 itself permits
   any one authorized signature for NO-GO. The
   GO/NO-GO decision is complete at this step. No GO archive upload or new
   publication destination is required; the storage-first ceremony still
   needs its existing storage configuration.

Both coordinator and release signer need the new Relay guide for the AWS path;
the pinned proof-tool remains unchanged. The handoff is unavailable to old
guides, which retain the manual public-file route. Frozen signed ceremony
definitions and existing prepared decisions remain byte-for-byte unchanged.
An existing V5 release signer may select the new launcher between completed
operations through `ceremony upgrade --role release-signer`; it retains the
original network-disabled signing image. The signer update refuses unfinished
local actions and must pass an exact v0.6.0-to-target continuation test before
use in an ongoing production ceremony. The coordinator selects its update
separately. See [release-signer upgrade](../release-signer-upgrade.md).
The AWS path requires the configured private inbox bucket and grant-role
issuer. The coordinator issues exact scoped grants through `D → 6`; no signer
AWS profile is required. The offline release-signer profile continues to
reject storage credentials. The keyless handoff is a separate `start.sh`
action and never mounts a grant in the signing container. Dedicated permanently air-gapped
signer hosts cannot use the AWS return action themselves; they use a separate
keyless transfer station for the public signature or the manual fallback.
Before showing questions, Relay checks the signed policy and stops if it
requires any optional auditor, external signoff, witness, or mirror. The
manual reviewed V5 draft remains available for those policies.

## Questionnaire and generated evidence

Question set V2 uses numbered choices (the number or full label is accepted).
The displayed `[value]` is a real saved answer or safe default; Enter accepts
it. `Example (not saved): ...` gives a format example only. No example is
silently submitted. Invalid choices repeat the same prompt without exiting.
`:save` retains a partial questionnaire; reopening resumes at its first
unanswered question. `:back` revises the preceding answer. No favorable
choice is a default: choices start at `Unknown`, while free text starts at
`Not established` or `Not assessed`. The coordinator reports reviews by other
people as attributed reports, not forged approvals. Relay records who answered
and when. It never requests private keys, seeds, randomness, credentials, or
private infrastructure details.

Every favorable review choice means **accepted with no unresolved blocker**.
`Review accepted; blocker remains`, `Rejected`, `Not reviewed`, and `Unknown`
cannot yield a passing gate. Positive free text is never semantically
certified by Relay. A reviewer/date answer uses `Name; YYYY-MM-DD UTC`; the
deployment target uses `Network; application or service`. Both are parsed only
to populate the existing V5 fields; a missing half prevents a passing gate.

**Pinned source release** — Relay displays the exact source commit:

1. Review outcome: accepted without blocker, accepted with blocker, rejected,
   not reviewed, or unknown.
2. Reviewer and UTC date.
3. Source, build, and release checks.
4. Findings, limits, and exceptions.

**Exact circuit rehearsal** — Relay displays the signed circuit binding:

5. Did the reviewed rehearsal use this exact signed circuit?
6. Rehearsal review outcome, including a distinct unresolved-blocker choice.
7. Runner/reviewer and UTC date.
8. What ran and its results.
9. Differences, failures, unchecked scope, and limits.

**Deployment and operation**:

10. Network and application, contract, or service.
11. Approval, preparation, and deployment owners.
12. Predeployment checks of signed GO, final release, and exact key.
13. Activation conditions and procedure.
14. Halt or rollback procedure and irreversible limits.
15. Postdeployment check and owner.
16. Reviewer and UTC date.
17. Plan review outcome, including a distinct unresolved-blocker choice.
18. Findings and limits.

**Participant assurance** — one shared section covers both phases. It first
asks whether the shared review truly covers every authenticated contribution.
Host security, randomness, and cleanup each have their own reviewer/date,
checks/findings/limits, and outcome. These can name different reviewers.
For every accepted `(phase, position, participant)` tuple, Relay then shows
the authenticated identity and asks for the actual host label plus three
independent outcomes: host security, fresh randomness, and cleanup. Each topic
may be `Covered and accepted; no unresolved blocker`, `Separately accepted; no
unresolved blocker`, `Review accepted; blocker remains`, `Rejected`, or
`Unknown`. A separately assessed or adverse topic also asks for specific
findings/limits and its own reviewer/date. A changed host or cleanup failure
therefore cannot be hidden behind one blanket answer. Shared acceptance counts
for a tuple only if shared coverage, that topic's shared review, and that
tuple's topic answer all affirm it. Relay rejects missing, duplicate, or stale
tuples before assigning `PASS`; proof-tool checks resulting report bytes, but
does not establish human truth.

**Final review**:

The final review follows every contribution: is there another known reason to
withhold GO, and what are the final findings and limits? Six accepted
contributions require 54 ordinary prompts, versus 114 in V1; exceptions add
topic-specific follow-ups. A shorter single-answer-per-contribution form was
rejected by adversarial review because it could conceal different hosts or
topic-specific blockers.

Relay derives the outcome from all 13 V5 gates; there is no independent GO
choice that can contradict them. A favorable human gate requires the
corresponding review to have happened, concrete reviewer/date/scope/findings,
an explicit favorable structured conclusion, and no unresolved blocker.
Structured unknown, incomplete, failed, rejected, or unresolved-blocker
answers map to `PENDING` or `FAIL`. Each review topic asks for a structured
unresolved-finding answer as well as free-text findings and accepted limits.
The final withhold question maps to the formal-checklist gate. Package-derived
gates come only from authenticated records and signed policy. Free-text
findings remain visible to both signers, but Relay does not infer success from
prose or claim it can detect every contradiction in a human narrative. Before
signing, each signer sees narrative findings alongside the derived gate result
and must stop if they disagree.

Relay generates `source-release.json` at V5's canonical path, an exact-circuit
rehearsal report, a deployment plan, a Markdown formal checklist, and
one host, one randomness, and one cleanup aggregate report. Each aggregate
lists every accepted contribution by phase, position, and participant,
identifies the review that covers it, and makes gaps visible. V5 allows at
most 32 evidence references per gate and bounds each report to 16 MiB, so
the generator checks those limits before preparation; the maximum 20 plus 20
contributions must fit. Each report states that it was generated from the
coordinator's attributed answers; naming a reviewer does not create that
person's signature. The checklist indexes the 13 gates and the other gates'
exact evidence hashes without repeating every answer. For its own gate it
records path and status, not its own digest; the canonical draft binds the
checklist hash after its bytes are fixed. Relay writes the
V5 `decision-draft.json` with explicit auditor, external-audit, gate, and
gate-evidence arrays, and the circuit, source, policy, release, and candidate
bindings read from authenticated files. The generated reports are public
decision evidence. The signer must read them; proof-tool verifies their bytes
and bindings, not the truth of the statements.

## Preparation and recovery rules

The private resumable questionnaire is bound to ceremony ID, candidate ID,
final checkpoint digest, signed policy digest, coordinator identity, and a
question-set version. A previously saved V1 form resumes under V1 rules,
without rewriting its attributed answers. A changed binding stops generation and requires review;
answers cannot silently transfer to a different release. Before preparation,
the coordinator may correct answers with `:back` or the final `EDIT ANSWERS`
action. Once a private preparation
intent exists, the exact questionnaire bytes and decision timestamp are frozen:
retry skips questions and verifies the saved intent before repeating proof-tool
preparation. After preparation, evidence and decision bytes are immutable.
Enabled external audits still require V5 signed reports
even for NO-GO, because V5 validates their count separately from outcome.
The auditor list must match the verified release package.

Before promotion, Relay renders the generated evidence and V5 draft in a
protected, resumable private staging directory on the same filesystem. It rejects symlinks,
unexpected files, path traversal, size-limit violations, duplicate names,
and conflicting references, then checks every generated byte and digest.
A durable private intent records ceremony and candidate bindings and each
proposed output hash before anything enters `ceremony/public/decision/`.
The pinned `decision prepare` verifier requires the entire signed final-release
tree, not only the generated decision reports, and it rejects release files
with multiple hardlinks. Relay therefore builds a fresh private evidence root
with independent files for every authenticated public snapshot file and the
staged reports. It uses filesystem clones where supported and streamed copies
otherwise, rejecting collisions and unexpected file types. It checks source
and staged hashes before preparation and again after the pinned tool returns,
including on tool failure. A clone/copy can need significant temporary disk
space; failure leaves canonical public files untouched. The tool output goes to a
fresh private check file. Relay compares that deterministic output with any
retained staged output, validates the complete decision and referenced
evidence, then durably promotes the whole staged decision directory to the
previously absent canonical path. Recovery distinguishes absent output, a
complete matching output, and partial or conflicting bytes; only the first
two can resume automatically.
Private staging and intent files are excluded from the archive.
The public decision tree contains only canonical `decision.json`, decision
signatures, and referenced `evidence/` files; no draft, intent, questionnaire,
or transport manifest enters it. Relay tests this against the current archive
allowlist.

Before promotion, a retry compares the intent, staged files, draft, and
deterministically regenerated decision byte for byte. It never overwrites a
different answer generation, prepared decision, signature, or archive. Once
promoted, an existing decision is retained and directed to the proof-tool
review/sign/verify path; Relay does not regenerate it from possibly changed
answers. Successful preparation is the edit cutoff. Corrections after that
require a separate reviewed supersession or recovery procedure, not an
in-place rewrite that could reuse a signature over stale evidence. Keep the
existing manual work-root recovery path.

## Archive sharing and independent verification

After packing, the archive can be transferred by any chosen means. An
optional, separate sharing action may upload the exact archive to configured
storage with a create-only content-addressed key or export it for GitHub or
another host. A hosted copy is downloaded and compared by hash to the retained
archive. This is a transfer check, not a second approval or mathematical
replay. The new flow removes the separate `SIGN GO PUBLICATION` action and
fixed official-publication pointer. Hosting is never required to obtain GO.
The upgraded coordinator guide must remove old `A`/`G` choices from this
pointer-free path, reject direct dispatch to them for its decision state, and
change the packer's post-success instruction so it no longer tells the
operator to choose `A`. One decision cannot enter both publication models.
Existing signed
publication records remain readable and legacy verifier behavior stays
compatible.

For the first release, an independent verifier downloads the complete
archive, runs `relay verify-ceremony --archive FILE`, requires top-level
`passed: true` and `checks[name=production-approval].status: passed`, and
manually compares the report's `ceremony_id` with one obtained through an
independently trusted channel. The ceremony ID hashes the signed definition,
including its coordinator identity; archive-only verification itself still
labels trust as archive-supplied, so the verifier must make and record that
independent comparison. For archives above the CLI's default 64 GiB expanded
limit, the guide estimates disk space and uses `--max-expanded-bytes`
explicitly. The current report will show
`officially_published: false` when no old pointer was checked. That does not
negate the signed V5 GO. Verification establishes historical approval at the
decision time, not that the host has the latest decision. A later NO-GO or
withdrawal can leave an older GO archive mathematically and cryptographically
valid; applications needing current approval need a separate trusted status
process.

A later public-verifier CLI can automate the expected-ceremony-ID comparison
and explicitly distinguish archive validity from hosted-copy matching. It
must not treat an archive-provided ID or a URL as the independent trust input,
and must not claim the archive is the latest decision. This later verifier
  release needs report-schema and compatibility tests; it is not part of this
  guided-decision release.

## AWS handoff and recovery

### Earlier release-review handoff

The coordinator and release signer also exchange public files *before* the GO
decision. The draft menus add a public AWS release-review snapshot transfer and
a private-grant signed-package return. The existing local directory handoff is
retained for recovery. These transfers are separate from the AWS decision
handoff below and still require two-host qualification before merge.

After the coordinator freezes its review, an online, keyless signer action must
download the exact authenticated public snapshot from the configured AWS-backed
public origin into a fresh bounded directory. The coordinator gives the signer
the expected ceremony ID, coordinator-key fingerprint, signed update and
checkpoint digest through the agreed independent channel. The download is
transport only: the offline guide must still authenticate the signed history,
all required hashes, the exact review checkpoint, and the already trusted
coordinator key. It must reject a changed or partial retained snapshot and
must not use an unqualified "latest" state as an approval. The snapshot is
public, so it needs no private read grant; a grant must not be introduced merely
to fetch public objects.

After offline review and release signing, the signer exits the offline guide.
An online, keyless `start.sh` action accepts a coordinator-issued temporary
grant scoped to the exact signer, frozen review checkpoint, ceremony and one
immutable release-package attempt. It checks the package's closed inventory
and exact signed binding before uploading, uses resumable create-only delivery,
and publishes the completion manifest last. The signing key and AWS grant must
never share a container mount. The coordinator's `start.sh` fetches the exact
attempt, verifies the signed release package, and records the final-release
checkpoint. Keep the existing manual public-directory import as an explicit
fallback; neither route may silently overwrite or replace a conflicting
retained package. Expired grants can be renewed for the same immutable signed
package without repeating offline signing.

Reuse the existing release-grant/inbox verifier and upload-station delivery
logic where their bindings match V5, but do not assume the legacy upload
station's role setup or prompts are appropriate for the signer's `start.sh`.
Test a real two-host menu path, wrong ceremony/signer/checkpoint/grant, partial
downloads and uploads, hash or signature mismatch, restart after each boundary,
grant renewal, conflicting direct import, and proof that no signing key or AWS
credential enters the wrong container. The earlier release handoff is a
separate qualification gate from the GO-decision handoff.

The first release adds the signer packet display and AWS return path to both
guides. The signer online transport action uses only the coordinator-issued
short-lived private grant and never opens the signing key or launches a signing
container. No persistent AWS signer profile or coordinator storage credentials
are copied to the signer. A private inbox object is not itself
trusted: the coordinator uses the authenticated assignment, exact release and
decision bindings, and proof-tool signature verification. An attacker who can
write a conflicting object can delay delivery, but cannot create a valid
decision signature. The UI makes this failure visible and permits a fresh
transport attempt or manual return, never silent acceptance.

Handoff metadata records the exact ceremony, candidate, final checkpoint,
decision digest, signer role and identity, object digests, and immutable AWS
keys. It lives outside the canonical public decision tree and never enters
the V5 archive. Publication of the private packet is create-only; its completion
manifest is last, so interrupted uploads are not offered as complete. The
signer rejects cross-ceremony, stale-release, wrong-signer, wrong-digest,
oversized, extra, and symlinked content before any signing prompt. Signature
upload is create-only and idempotent for identical bytes. The coordinator
does not overwrite a manually returned signature with a conflicting AWS
object. Every retry reports which exact binding was retained. No transport
retry triggers another signature, and no transport result changes V5's
signature threshold.

## Qualification and review

An independent design review must test the boundary between byte-verified
evidence and human truth, especially whether the UI can make a weak report
look mechanically approved. The first implementation must test with the
exact pinned proof-tool and current signer image, including:

- Correct GO and NO-GO answer mappings, every V5 gate, rejection of nonzero
  optional-policy settings, missing or contradictory structured answers, wrong ceremony,
  release, circuit or source, missing external-audit signoffs, wrong signer,
  missing/duplicate/stale accepted-contribution entries, and changed decision
  or evidence bytes. Use the real pinned proof-tool to prepare both outcomes
  from generated fixtures. Cover the zero-policy path and reject nonzero
  settings before the questionnaire. Test 16 MiB bounds for reports, draft,
  and decision. A later expansion must cover 1–16 signoffs; 17–20 remain
  blocked by pinned proof-tool.
- Interrupted questionnaire and generation, staging crashes before and after
  promotion, proof-tool preparation interruption and crash before/after the
  canonical no-replace promotion, symlinks, conflicting
  outputs, and an attempted edit after
  preparation or signature.
- Full V5 production-mode coordinator and upgraded signer `start.sh` journey:
  AWS packet publication and readback, authenticated signed snapshot import,
  offline signer review, both signatures, keyless public-signature upload,
  coordinator fetch and signature verification,
  staged archive assembly, one threshold verification against its extracted
  bytes, and independent archive replay. Also test a coordinator-only signed
  NO-GO archive. Mutate source evidence during staged
  assembly, the staged archive during verification, and archive bytes before
  final promotion; none may produce an accepted archive without fresh
  verification.
  Test the upgraded signer menu with the actual AWS packet, including
  transport-manifest placement outside the canonical decision tree and a
  documented, performed report-reading and hash-comparison handoff. Test the
  maximum 20-plus-20 contribution roster against the gate evidence and report
  size limits. Test wrong-bucket, wrong-key, stale decision, wrong signer,
  altered packet, partial upload, same-byte retry, conflicting-byte retry,
  missing AWS permission, expired download and upload grants, renewed upload
  access without another signature, forbidden writes with a download grant,
  forbidden reads outside the packet, neighboring object keys, grant file
  permissions and diagnostic exclusion, and switching between AWS and manual
  return. The real AWS probe must demonstrate that the session policy reduces
  the configured grant role's bucket-wide base permission.
  Optional archive hosting and hosted-copy readback remain separate.
- Public verification with the independently trusted ceremony ID, altered
  archive, NO-GO archive, expanded size above 64 GiB with explicit resource
  setting, and an older GO followed by a later NO-GO without either report
  claiming to know the latest state.

No proof-tool schema change is required to implement this guided generation
journey for the stated zero-optional policy scope. Policies requiring more
than 16 external security-audit signoffs need a proof-tool fix. A future decision policy that
drops V5's human gates also requires a proof-tool change and a new ceremony
definition; it is a separate design.

## Adversarial review outcome

The independent review loop found and the design resolved these implementation
traps: a 32-reference gate cap versus up to 40 accepted contributions (use
bounded aggregate assurance reports); omitted or duplicated contribution
coverage (compare exact authenticated tuples); an unchanged signer CLI that
cannot display reports (make reading and hash comparison an explicit manual
handoff); draft or manifest files rejected by the archive allowlist (keep
them outside the canonical decision tree); the checklist's impossible
self-hash (bind its digest only in the draft); old publication actions that
could mix models (guard dispatch as well as menu text); a file-change window
between verification and packing (verify the extracted staged archive and
check its hash before and after); and the different GO and NO-GO signature
thresholds. The final focused pass found no remaining blocking contradiction.
This is a design review, not an executed end-to-end test or security
certification. The qualification tests above remain required before release.

A second independent pass found the external-audit limit: 17–20 signed
signoffs are allowed by the policy type but impossible to represent under
V5's 32-reference gate cap. The first guided Relay implementation is narrower:
it supports zero optional signoffs and fails early for nonzero frozen policies.
Supporting 1–16 needs package-evidence plumbing; 17–20 needs a proof-tool
change. That pass also clarified draft/decision size preflight,
coordinator accountability for guided NO-GO, independently trusted ceremony
ID comparison, and the verifier's expanded-size setting.

An independent review of the AWS extension found that the signed ceremony
does not authenticate an AWS destination, the current signer guide rejects
storage credentials, and a private readback needs read as well as write
permission. The revised design treats the bucket and key as discovery hints,
uses a separate keyless online signer action, and checks exact ceremony,
checkpoint, decision, and signer bindings. It reuses the signed public
snapshot objects instead of uploading a potentially huge second copy, and
keeps pre-GO review reports in the private inbox. Its completion manifest
and optional supporting files stay outside the canonical decision tree. A
follow-up review of the temporary-grant revision found that a credential
spanning offline signing can expire, and that the ordinary contribution grant
has overly broad read/write scope for this handoff. The design now issues
separate read and upload sessions, restricts upload to one exact key, and
allows upload-grant renewal without repeating a signature. AWS limits STS
inline session policy text to 2,048 characters, so the read policy covers
only this decision's `objects/*` prefix and exact manifest key rather than
enumerating every object.
