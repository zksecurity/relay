# Guided V5 production decision

Status: implemented in the draft Relay worktree; full two-host AWS and Linux
ceremony qualification remains pending before release. The change affects the
coordinator and release-signer guides. It does not change the pinned proof-tool,
the signed ceremony definition, or an existing prepared decision. The AWS
handoff is transport, not a new approval or a substitute for signature checks.

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
4. On the release signer's **online, keyless** `start.sh` handoff screen,
   separate from the offline signer guide, the signer selects **Download
   decision packet from AWS**. The coordinator gives the signer the public
   private AWS handoff location, final-checkpoint digest, and decision digest;
   these are discovery hints, not trust anchors. The signed ceremony does not
   contain an AWS bucket or origin. Relay validates the configured bucket and
   fixed key shape, checks the downloaded packet against the ceremony ID,
   final-release checkpoint, and decision digest supplied for comparison,
   and displays those bindings. It
   never selects a "latest" packet from an AWS listing. The separate online
   transport profile has bounded read permission to this handoff prefix. It
   downloads the snapshot objects from the published origin and decision
   objects from the private handoff into a fresh directory with strict
   per-file and total limits, and checks the manifest and every object hash.
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
5. After offline signing, the signer exits the signing guide, reconnects,
   and chooses **Upload my public decision signature** in the keyless
   `start.sh` handoff. A separately configured signer AWS identity has only
   write and readback permission for the ceremony's private
   inbox signature prefix, and bounded read permission for the decision
   packet prefix; it has no published-bucket write permission and is
   never mounted with the signer key. The online action reads only the public
   signature and authenticated public metadata; it cannot launch the signer
   container or open `signing.hex`. Relay uploads the exact public
   `release-signer.sig` under a ceremony, release, decision digest, and signer
   ID-bound immutable key and reads back its size/hash. This identity is a
   transport prerequisite, not a decision signer; without it, the manual
   public-file return remains an explicit fallback. The coordinator's
   **Fetch decision signature from AWS** action downloads only that expected
   key with a strict size bound into a fresh path, checks its recorded hash,
   and promotes it into the canonical decision tree without replacing a
   different file. `D → 3` then checks the cryptographic signer/decision
   binding and complete V5 threshold with pinned proof-tool; fetch alone
   never reports the decision verified.
   A missing, partial, duplicate, or mismatched object never counts as an
   approval. If the coordinator signs NO-GO, V5 permits its one authorized
   signature; signer countersignature is optional.
6. `D → 3` checks the authenticated returned public signature and builds a staged archive
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
The AWS path requires the configured private inbox bucket,
and a separately authorized signer upload identity. Relay checks these before
offering the path and never silently switches to manual transfer. The offline
release-signer profile continues to reject storage credentials. The keyless
handoff is a separate `start.sh` action with a distinct transport profile, so
the online step cannot weaken that guard. Dedicated permanently air-gapped
signer hosts cannot use the AWS return action themselves; they use a separate
keyless transfer station for the public signature or the manual fallback.
Before showing questions, Relay checks both the signed policy requirement
and the actual external-audit report/signoff count against the 16-signoff
limit. It stops on a larger count instead of silently dropping a reviewed
report or generating an unrepresentable decision.

## Questionnaire and generated evidence

Questions use `Yes`, `No`, `Unknown`, and `Not reviewed yet` where applicable,
with no affirmative default. Structured review conclusions are `Accept`,
`Reject`, or `Incomplete or unknown`; the rehearsal outcome is `Pass`, `Fail`,
or `Incomplete or unknown`. The coordinator reports reviews by other people
as attributed reports, not forged approvals. Relay records who answered and
when. It never requests private keys, seeds, randomness, credentials, or
private infrastructure details.

**Pinned source release** — Relay displays the exact source commit:

1. Was the pinned source release reviewed?
2. Who reviewed it, and when?
3. What source, build, and release checks were performed?
4. What were the findings, limits, and exceptions?
5. Did the reviewer conclude this pinned release was acceptable for this ceremony?
6. Is any source or release issue still blocking its use?

**Exact circuit rehearsal** — Relay displays the signed circuit binding:

7. Was this exact circuit rehearsed and reviewed?
8. Who ran and reviewed the rehearsal, and when?
9. Did the reviewed rehearsal use the displayed circuit binding?
10. What was run, and what were the results?
11. Did the exact-circuit rehearsal complete successfully?
12. What differed from this ceremony, failed, or was not checked?
13. Is any rehearsal finding still blocking production use?

**Deployment and operation**:

14. Which network and application, contract, or service will receive the key?
15. Who approves, prepares, and performs deployment?
16. How will they check signed GO, final release, and the exact verifying key before deployment?
17. What are the activation conditions and procedure?
18. How can use be halted or rolled back, and what cannot be reversed?
19. Who checks the deployed key and application state afterward, and how?
20. Who reviewed this procedure, when, and with what findings?
21. Did the reviewer approve the procedure for this ceremony?
22. Is any deployment or operational issue still blocking production use?

**Participant assurance** — repeat for each accepted contribution, showing
its authenticated phase, position, and participant. A review may cover
multiple contributions only when the coordinator explicitly names them and
confirms the relevant conditions were unchanged. Relay derives the exact
accepted `(phase, position, participant)` set from the authenticated final
release, requires exactly one answer entry for each tuple and each assurance
topic, and rejects missing, duplicate, or stale tuples before assigning
`PASS`. Proof-tool checks the resulting report bytes, but does not establish
this semantic coverage itself:

23. Was the participant's host security reviewed?
24. Who reviewed it, when, what did they check, and what remains unverified?
25. Did the reviewer accept that host for this contribution?
26. Is any host-security issue unresolved?
27. Was the randomness source and generation process reviewed?
28. Who reviewed it, when, what did they check, and what remains unverified?
29. Did the reviewer accept that randomness process for this contribution?
30. Is any randomness issue unresolved?
31. Was cleanup reviewed?
32. Who reviewed it, when, what did they check about snapshots, memory dumps,
    swap, backups, and retained randomness, and what remains unverified?
33. Did the reviewer accept the cleanup outcome for this contribution?
34. Is any cleanup issue unresolved?

**Final review**:

35. Is there any other known reason to withhold GO?

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
question-set version. A changed binding stops generation and requires review;
answers cannot silently transfer to a different release. Before preparation,
the coordinator may correct answers. After preparation, evidence and decision
bytes are immutable. Enabled external audits still require V5 signed reports
even for NO-GO, because V5 validates their count separately from outcome.
The auditor list must match the verified release package.

Before promotion, Relay renders the generated evidence and V5 draft in a
fresh private staging directory on the same filesystem. It rejects symlinks,
unexpected files, path traversal, size-limit violations, duplicate names,
and conflicting references, then checks every generated byte and digest.
A durable private intent records ceremony and candidate bindings and each
proposed output hash before
anything enters `ceremony/public/decision/`. It promotes into a previously
absent decision directory, retains the exact draft privately outside
`ceremony/public/decision/`, and runs proof-tool
`decision prepare` against the public evidence root with output directed to a
fresh private staging file. Relay validates the complete output, then durably
promotes it to the canonical decision path without replacing any existing
file. Recovery distinguishes absent output, a complete matching output, and
partial or conflicting bytes; only the first two can resume automatically.
Private staging and intent files are excluded from the archive.
The public decision tree contains only canonical `decision.json`, decision
signatures, and referenced `evidence/` files; no draft, intent, questionnaire,
or transport manifest enters it. Relay tests this against the current archive
allowlist.

On retry, Relay compares the intent, public files, draft, and prepared decision
byte for byte. It resumes only the same operation; it never overwrites a
different answer generation, prepared decision, signature, or archive. Successful
preparation is the edit cutoff. Corrections after that require a separate
reviewed supersession or recovery procedure, not an in-place rewrite that
could reuse a signature over stale evidence. An already prepared V5 decision
is detected and offered for review/sign/verify without regenerating from
answers. Keep the existing manual work-root recovery path.

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

The first release adds the signer packet display and AWS return path to both
guides. The signer online transport action uses a distinct profile and never
opens the signing key or launches a signing container. Its AWS credentials
are restricted to the ceremony's private inbox handoff prefix; the signer
needs no coordinator storage credentials. A private inbox object is not itself
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
  missing AWS permission, and switching between AWS and manual return.
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
and optional supporting files stay outside the canonical decision tree.
