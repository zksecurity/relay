# Compatibility and activation contract

Target design; see [scope and implementation status](ceremony-contract-compatibility-design.md).

## Authority

Protected-main release CI publishes an attested declaration for each reviewed
source-app → target-app pair, role and platform. No automatic compatibility from
version numbers or matching Proof-tool hashes. Existing ceremonies keep their
original release identity; a separate local record selects the current app.

A declaration binds:

- Original ceremony runtime release(s), source app and target app commits.
- Role, host OS/architecture, Docker platform and exact replacement online image,
  if any. Participant/signing execution images stay original.
- Approved in-image Proof-tool hashes, protocol/storage format and setup contract.
- Local profile/journal versions read and written; original workflow semantics.
- Supported activation states and operation kinds; named, versioned recovery
  adapters for pending work, or a requirement to finish it under its old runtime.
- Safe old-version reentry policy and required execution-exclusion capability.
- Public qualification-report digest for that exact candidate and covered cases.

Authenticate both release maps, the declaration and installed native target.
Measure actual in-image Proof-tool; do not substitute a host binary measurement.
An independently authenticated original definition must approve that binary.
Retain verified metadata/provenance material locally for offline operation.
Local records remember that verification, but are not a new trust authority.

Before initialization, bind the saved draft and original setup/software manifest
instead of a nonexistent signed definition. Record absent identity/definition
explicitly; ordinary verified setup transitions bind them when first created.
Do not regenerate existing keys, initialize during upgrade, or ignore mismatches.

Draft selections keep a stable installation descriptor even when setup later
creates the shared profile. A mandatory local binding file grows in atomic
identity, definition/key/signature, storage and frozen-initialization groups.
Losing that file is an error, not permission to start again. Identity continuity
records generation or explicit public-identity review; it does not prove private
key possession. Definition signatures and role assignments still pass the
original verifier. Existing frozen initialization inputs remain pinned even if
initialization stopped before a valid signed definition existed. Companion
architecture binaries come from the original attested software manifest.

The current coordinator-only v1 declaration cannot express this full contract.
Add a strict, bounded v2 schema/reader and explicit producer; retain v1 behavior.
Unknown fields, duplicate keys, unsupported adapters or missing coverage reject.
Do not silently reinterpret existing v1 declarations as broad authorization.

## Current app versus original ceremony

Activation preserves frozen bindings and existing evidence, not frozen progress.
Normal operations can advance the same journal formats; explicit credential
reference renewal remains possible. An effective-runtime resolver
combines their frozen bindings with the active, verified application selection.
Every entry point uses it: `start.sh`, setup/resume, operations, saved actions,
participant supervisor, read-only inspection and transport subprocesses.
Per-operation saved runtimes take precedence over the default for new work.

On a second update A → B → C, authenticate A's frozen ceremony runtime and the
currently active B → C authorization. That declaration must also cover A's
ceremony and every inherited operation's runtime, state and adapter version.
Preserve an explicitly supported adapter or replace it with a qualified one;
otherwise refuse. Do not assume A → C or transitivity.
Keep a create-only selection history with predecessor digest, role/identity,
canonical workspace identity, preserved bindings, app/runtime choices and any
pending-operation adapter mappings. Reject copied selections in another role
folder. Do not copy keys, grants or credential contents into this history.

Credential rotation may replace only protected credential references, after
checking the same ceremony target, principal and allowed scope. It does not
change signed storage settings or erase pending attempts. Avoid hashing a whole
profile in a way that accidentally makes authorized credential renewal impossible.
If the provider cannot expose principal/scope, require administrator-authenticated
binding plus scoped access checks; a successful read alone does not prove equivalence.

## Activation transaction

`original → prepared → selected → entry-point-updated`; activation is local.

1. Authenticate software; download images before any offline disconnection.
2. Acquire role/workspace locks and establish execution safety. Inventory retained
   work without changing it. Build a bounded plan for every pending operation.
3. Show the plan; obtain approval. Recheck local bindings, process/container state
   and relevant backend facts after the prompt. If the plan changed, ask again.
4. Write and sync a complete immutable selection generation, then atomically
   select it using the expected previous selection. No partially written record
   is active. The initial generation names the original profile as predecessor.
5. Back up the original generated `start.sh` locally; atomically update it only
   if its bytes still match the reviewed original or already-installed result.
   Do not overwrite custom/operator-edited scripts; offer the exact resume command.
   Clearly report “Update selected; custom start script unchanged”, not full repair.

Before selection, failure leaves old software active. After selection, rerunning
upgrade finishes entry-point repair idempotently. No ceremony operation occurs as
part of activation. Retrying activation is not retrying a contribution/upload.
Subsequent work uses the selected generation only after revalidation under lock.

Do not restore old progress from backups after target operations run. A rollback
is another explicitly qualified software selection over the current evidence.
Keep original binaries/images available for pinned pending operations; if missing,
obtain exact verified bytes or stop. No substitution with a newer similar image.

Eligibility requires tested safe reentry by every previously activated/retained
app version able to open this workspace, including target-created pending work.
Otherwise a concrete, tested predecessor-exclusion mechanism is mandatory. For
released binaries that ignore selection metadata and lack that mechanism, refuse
the pair. An operator promise or a backup alone cannot waive unsafe reentry.

## Offline and website boundaries

The final signer prepares verified update metadata and binaries before going
offline. If already offline, a separate connected preparation station assembles
the exact native binary, pinned images, declarations and offline-verifiable
provenance bundle. Transfer only that bundle; never export the signing key.
The signer verifies it against previously trusted release-provenance roots and
its own frozen review package, not a public key bundled as its own authority.
If the required offline verification is unavailable, stop; do not reconnect or
skip checks automatically. Offline activation makes no GitHub/storage calls and
claims neither global freshness nor revocation knowledge beyond the prepared
trust material. Recheck the exact review package before signing; the upload or
coordinator acceptance step must reject a signature for a superseded review.

Tessera retains the original frozen setup/release; it must not rewrite downloaded
setup JSON or infer authorization from a newer website default. Optional reporting
of the active application is separate from the signed setup. Its server must test
the selected client/API pairing without changing grant scopes or trusting client
version claims. If an existing API rejects it, block that pairing until a compatible
server change is deployed; do not disguise the target app as the original binary.
Standalone ceremonies do not require Tessera. No setup-v2/v2r2/v3 bytes change.
