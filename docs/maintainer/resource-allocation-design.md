# Operation resource allocation

Status: implementation in progress; not release qualification.

Resource selection is local execution policy. It must not change signed ceremony
inputs, approved proof-tool identities, or mathematical verification. Proof-tool optimizations ship
first, followed by one Relay release updating the pins and integrating resource/UI
changes for a new ceremony.

## Agreed PR and release order

Updated operator decision: two release stages, superseding the previous
Relay-only → proof-tool → Relay pin-update sequence.

1. Publish the proof-tool optimization release first, after protected-main checks,
   both architecture checksums and attestations. Persistent key caching is deferred.
2. Ship one Relay PR/release that updates `release/role-images.json` to those exact
   verified assets and includes compatible resource-allocation, UI and integration
   changes. Qualify the full V5 ceremony workflow and required cross-repository
   gates before release. No separate Relay-only release retaining old pins is planned.

Choose version numbers from final scope and `release-versions.md`; earlier
provisional v0.5.0/v0.6.0 two-release numbering is superseded. Start a fresh ceremony
with the approved released pairing; never replace its active computation's tools.
This is release ordering, not permission to publish during documentation work.

## Selection and recovery

Resolve limits immediately before a new operation, within saved user caps. Show
Docker capacity, the selected allocation, and an elapsed heartbeat. Defaults remain
2 CPUs / 6 GiB container memory / 4 GiB Go target / GOGC 25 until exact-circuit
measurements qualify alternatives. Total Docker memory is not available memory.
Keep CPU quota and GOMAXPROCS consistent; retain non-Go memory headroom and equal
memory/swap limits. Do not resize a running operation.

A durable operation or attempt identity owns its allocation. Credential rotation,
profile labels, and compatible CLI upgrades cannot change that identity. Retrying
retains the original allocation; a demonstrably new attempt may select new limits.
Command text alone is insufficient where the same command can represent several
operations. Each mutating caller must identify its durable operation or explicit fresh
attempt. Read-only inspection should not become permanently tied to a historical
allocation merely because its command text repeats.

Independent recovery review found a concrete retry counterexample: finalization
previously regenerated its timestamp when reconstructing the command, changing
the argv digest for the same pending operation. The implementation replaces generic command-hash
allocation with an explicit ceremony/predecessor/action/attempt/step binding.
Existing allocate/accept/reject intents supply that identity; lifecycle actions
use a private durable intent with a retained timestamp and separate step
allocations. Retain exact command and runtime as checked metadata, not the sole
operation identity. A changed predecessor or explicit attempt permits a new
allocation; changed immutable metadata on a retry must fail.

For legacy coordinator intents, absent resources retain 2/6/4/25 defaults.
At the first upgraded lifecycle startup, persist the authenticated current
checkpoint and pending action as the migration boundary. Ambiguous resource-less
steps at that boundary remain legacy until the checkpoint advances; use exact
validated retained invocation limits if available. A fresh ceremony needs an
explicit new-format creation marker. Missing outputs alone never prove a fresh
attempt. Test interruption before launch, timestamp stability, later attempts
with identical argv, invalid metadata, corrupted records, migration interruption,
and independence of derivation/recording/signing steps. The implementation below has local regression coverage; production and upgrade
qualification remain required. Design review is not executed test evidence.

Coordinator allocation/acceptance/rejection now use version-2 intents containing
the selected resource limits, saved atomically with the existing operation
identity before launch. Existing version-1 intents migrate with explicit legacy
defaults, preserving attempt, timestamp, predecessor and output. These three
launch paths consume intent resources directly rather than command-hash records.
Missing/invalid v2 resources fail closed.

Coordinator lifecycle steps now retain allocation, timestamp, command, output,
image/platform and trust/key mount identity. Closure, beacon, seal, derivation,
finalization, evidence review and final checkpoint-recording paths use explicit
predecessor/step bindings. Changed commands are rejected before launch. New
journals record resource-policy version 1; older journals retain version 0.
The first authenticated head establishes a durable resource origin before guide
choices are offered. Legacy steps at that head keep original defaults; later
heads can choose current preferences. An existing origin cannot be reclassified
as fresh on reopening. Retained timestamp-only step records migrate with legacy
limits. Upgrade inventory validates both origin and step records. Tests cover
interruption, preferences, repeated commands at later heads, separate steps and
corrupt state. The remaining generic proof-command callers were audited below. Real upgrade
and ceremony qualification remains required before release.

Missing records are not evidence of a new operation. For pre-feature recovery,
use retained invocation and inspected container limits where available. Legacy
records without allocation fields retain the released defaults. Preserve invalid
or incomplete records and stop rather than overwriting them with preferences.

## Admission among Relay launches

Independent review rejected separate stopped reservation containers: they create
a second object that can become orphaned before its workload is identified.
Use the actual created workload container as the capacity claim:

1. Hold an OS advisory lock bound to the local daemon identity in an agreed shared
   directory. The first supported scope is cooperating local Relay clients;
   independent remote clients require a separate admission protocol.
2. Inspect running, paused, restarting, and admitted created containers. Account
   for each workload once, including nested inspection containers. Unknown or
   unbounded workloads prevent a confident automatic recommendation.
3. Check the requested allocation against remaining capacity and host reserves.
4. Persist exact operation intent, then create the actual workload with bounded
   limits and unique attempt labels. Save its ID before releasing admission.
5. Start/attach to that exact container. A lost create response requires identity
   and full-configuration reconciliation, never speculative creation of a second
   workload. Release its capacity only after verified terminal state/removal.

A client disconnect or syscall.Exec does not release the claim. An advisory lock
releases on process death; a stopped named lock container does not provide safe
crash recovery. Foreign containers cannot be adopted or removed based on labels
alone. Other Docker clients can still race admission: this coordinates Relay
launches, not an absolute host-memory guarantee.

## Qualification still required

Test simultaneous oversubscribing admissions; interruption before/after create,
ID persistence, start, attach, and completion; changed preferences/credentials;
legacy running operations without records; paused/restarting/unbounded external
workloads; inspection failure; nested workloads; and foreign name/label matches.

Measure 2/4/6 CPUs on the exact production circuit, including peak memory and
identical deterministic genesis output. Keep suggestions within validated bounds
and saved caps. Run full Relay tests, live ceremony and recovery gates, release
checks, and the exact-head Tessera integration gate before publication. The UI,
unit tests, and independent design review do not establish production readiness.

## Unbounded external workloads: reviewed policy refinement

Qualification found that the intended participant/signing hosts already run
unrelated services without CPU or memory limits. Strict rejection would make
these hosts unusable. Do not change those services or silently treat their
current usage as a bound. Provide two explicit daemon policies:

- `strict`: all relevant workloads must have known limits; automatic suggestions
  may use the validated capacity model.
- `operator-budget`: the operator assigns an aggregate CPU/memory budget to Relay
  despite identified unbounded external workloads. Automatic suggestions are
  disabled. This is an operator assumption, not a guarantee of spare memory.

Persist daemon identity/capacity, policy schema and mode, aggregate Relay budget,
and the acknowledged unknown workload IDs/resource configuration. Keep per-job
limits separate from the aggregate budget. Subtract Relay claims and bounded
external allocations conservatively. An unbounded Relay workload remains an
error in either mode. Do not let acknowledgment bypass allocation or identity
validation.

Explain: "Other containers have no memory limit. Relay cannot determine safe
spare capacity. You can explicitly assign Relay a budget; these containers may
still compete for memory."

Require renewed acknowledgment for a daemon/capacity change, new or replaced
unknown container, or relevant configuration/status change. Removal alone need
not invalidate it. Save policy atomically under the same admission lock and
reinspect immediately before create. Missing/corrupt policy blocks new admission;
it must not block inspection or cleanup of existing jobs. Never resize or kill
existing jobs to satisfy a changed budget.

The policy is implemented with tests for strict rejection versus explicit budget
acceptance, changed unknown sets, combined claims, invalid policy, inspection
failures and unbounded Relay jobs. Disposable Docker lifecycle qualification also
checked exits, duplicate rejection and auto-removal. This independently reviewed
policy still needs the full release and ceremony gates.


Release-signing audit: review and signing use explicit retained steps, including
stable review timestamps when the child fails before producing its report.
Read-only release verification uses current preferences for each invocation.
Enrollment recording creates a distinct staging attempt; allocation selection
honors the authenticated migration boundary before retaining that command's
limits. Other production callers of the generic profile runner perform online
Relay transport/commit commands. Disposable live-test fixture preparation also
uses the generic runner. Ordinary, contribution and renewable-credential launches
announce their allocation immediately before starting.


Guided suggestions now offer only the released 2/6/4/25 allocation after checking
strict inventory, host reserves and saved limits. Selection is explicit and
capacity is rechecked at admission. No suggestion is made for operator-budget
policy, unknown workloads, insufficient headroom or caps below that validated
configuration. Higher CPU recommendations still require production measurements.

## Deferred optimization integration

Persistent coordinator calculation caching is outside the current release. Do not
add cache mounts, MAC-key setup, cache controls or saved-key status messages in
Relay. Existing upload memo and workflow journal are retained; they are not the
deferred calculation cache. Cache-specific memory/recovery qualification does not
block the no-cache resource/UI integration.

Standalone direct-CLI durable attempt tracking is also deferred. Preserve Relay's
journal-before-launch protection and validate interrupted-generation/recovery
behavior. Do not advertise standalone crash-safe retry guarantees or treat missing
output as proof that randomness was never generated. Resource admission and memory
qualification for current operations remain mandatory.
