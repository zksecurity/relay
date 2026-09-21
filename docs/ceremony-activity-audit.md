# Exporting ceremony activity

Each initialized V4 role workspace can export a local activity report:

```sh
relay audit export --work /absolute/role/work --out /absolute/fresh-export
```

Save and exit the role guide before exporting. A busy workspace is rejected.
The fresh directory contains `report.json` and `report.md`. Exports never upload
anything, request a signing key, copy the workspace, or include raw command lines,
terminal output, credentials, grants, or host paths. Source IDs are hashes of the
workspace's random ID, allowing repeated exports to be matched without exposing
private paths or identity labels. Record which source belongs to which machine
when collecting the reports.

Combine exports on one machine, including a manually transferred signer export:

```sh
relay audit combine \
  --input /absolute/coordinator-export \
  --input /absolute/participant-1-export \
  --input /absolute/participant-2-export \
  --input /absolute/signer-export \
  --out /absolute/fresh-combined-report
```

The command rejects different ceremony or definition identities. Exact duplicate
imports are ignored; different snapshots from the same workspace remain visible
with a conflict notice. Imported report hashes and bounded import lineage preserve
provenance. The command does not independently authenticate imported observations
or verification claims, or assert that every required role submitted an export.

## Checking signed progress

By default, reports contain **unauthenticated local observations**, including
recorded operation attempts, results and recovery states. Successful execution
alone does not establish coordinator acceptance or erasure of secret material.

On a Linux host with the matching released proof tool, explicitly authenticate a
selected checkpoint against a separately trusted coordinator public key:

```sh
relay audit export --work /absolute/coordinator/work \
  --out /absolute/fresh-verified-export \
  --coordinator-key-file /absolute/trust/coordinator.hex \
  --mpc-ceremony /absolute/approved/mpc-ceremony \
  --checkpoint checkpoints/SELECTED/checkpoint.json \
  --checkpoint-signature checkpoints/SELECTED/checkpoint.sig
```

Checkpoint paths are relative to `work/ceremony/public`. Choose the actual pair
you intend to inspect; it is not assumed to be the latest. The proof executable
must match the installed Relay release's immutable pin. Do not take the trusted
key from the public evidence directory. Required flags or failed verification
return a nonzero status; a report written after verification failure says so.

This checks the definition and signed checkpoint ancestry, records exact hashes,
trusted-key fingerprint, verifier digest, accepted contribution counts and signed
phase/release progress. It does **not** replay contribution mathematics, certify
all historical payloads are present, verify host integrity, or prove global
freshness. The report itself is unsigned; another reader must reverify public
evidence instead of trusting a `passed` field. Combination labels these fields as
claims made by the exporting tool.

## Recording and gaps

New Relay builds retain sanitized diagnostics in an append-only activity log,
in addition to the existing last-100-event bug-report log. Selected V4 guide
actions record correlated starts and completions before and after execution.
A failed start write blocks the action. A failed completion write leaves the
action's result unchanged and warns the operator; it never repeats the action.
V4 operation journals supply more detailed contribution/recovery steps.

The report includes explicit coverage gaps. Setup/legacy diagnostic hooks are
best effort and uncorrelated; direct commands without those hooks, refresh
fetches, shell actions outside Relay, and pre-recording activity are not covered.
Existing truncated history cannot be recovered. Export currently requires an
initialized V4 journal, but retains earlier recorded setup observations once
that workspace is initialized. Local and diagnostic snapshots are captured under
locks separately; this is not an atomic snapshot of the entire machine.

Local sequence and hash-chain checks detect accidental edits, not rewriting or
deletion by somebody controlling the host. Clock timestamps do not establish
cross-machine causal order. The 64 MiB recording ceiling fails new starts rather
than discarding old events; reports/imports have a 32 MiB bound and fixed per-source
limits. There is no automatic rotation or truncation. A partial final log record
is exported as a gap and blocks new guide actions. Preserve the original log and
review recovery state before repairing it; never retry an operation solely because
its completion record is missing. Manual log repair is not automated by this
command.

The export contains summaries and hash references, not a complete public replay
archive. Keep the ceremony's public artifact archive separately. These commands
must not be described as recording every action on every host.
