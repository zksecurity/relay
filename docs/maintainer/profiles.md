# Prepare authenticated role profiles

The [onboarding helper](../role-onboarding.md) now collects the inputs and calls
these initializers. This reference explains the underlying commands for
maintainers and recovery. Onboarding prepares measured tool records and asks
participants to review the environment plan. Enrollment signatures still require
the enrolled owner's agreed authenticated signing procedure.

Stage the signed definition and signature under `CEREMONY_HOME/public`,
the storage config under `CEREMONY_HOME/config`, and mutable output under
`CEREMONY_HOME/run`. Keep the coordinator public key independently authenticated.

Approved-image preparation emits `relay-release-tool-identities-v1`, binding
measured tools to this launcher's source commit and embedded proof-tool pins.
It is a local measurement record, not a signature, compatibility-test result,
or independent proof of release approval. Downloads are authenticated separately
using GitHub provenance; profiles still authenticate the signed ceremony policy.
Legacy kit receipts remain readable. Do not reuse another installation's record.

## Participant: host paths

Set absolute host paths for every variable below; select one phase per profile.
Onboarding caches the pinned Linux proof tool under `work/approved-tools`.
The host hashes that file; Docker executes the image's tool at the fixed path
`/usr/local/bin/mpc-ceremony`. The host path need not match the image path.
The signed binary policy still governs the executable used for contribution.

```bash
"$RELAY" ceremony init-config \
  --home "$CEREMONY_HOME" --role participant --phase "$PHASE" \
  --execution-mode docker --docker-image "$CONTRIBUTOR_IMAGE" \
  --docker-platform "$LINUX_PLATFORM" \
  --ceremony-binary "$MPC_BINARY" \
  --coordinator-key "$COORDINATOR_KEY" \
  --tool-identity-receipt "$TOOL_IDENTITY_RECEIPT" \
  --signing-key "$SIGNING_KEY" --environment "$ENVIRONMENT_FILE" \
  --out "$ROLE_CONFIG"
```

The initializer verifies the tools, signed ceremony, key identity, and phase
assignment. Confirm the printed assignment with the operator.
Outputs are create-only. Correct the authenticated inputs and choose a new
output path after failure; do not edit the generated profile.

The contributor image/platform must match the verified release and the signed
binary allowlist. Preload the image before initialization: setup validates it
through Docker. Use `docker pull REPOSITORY@sha256:DIGEST` with the authenticated
map's contributor digest. Image approval never replaces the signed binary policy.

Use the participant's own key; the coordinator must not receive it.
Use the matching proof-tool v2 environment input with contributor-scoped
controls and `host_remnants_not_excluded: true`; do not reuse old environment JSON.
Remote Docker contexts and Docker Desktop on Linux are rejected.

## Other roles: container paths

Create profiles inside the online role image using the role's setup/open
command from its guide. Pass this tool command after `--`:

```bash
relay ceremony init-config --home /work/ceremony \
  --role "$PROFILE_ROLE" --identity "$IDENTITY_ID" --phase "$PHASE" \
  --coordinator-key /trust/coordinator-public-key.hex \
  --tool-identity-receipt /trust/tool-identity-receipt.env \
  --enrollment /trust/enrollment.json \
  --enrollment-signature /trust/enrollment.sig \
  --out "/work/ceremony/config/$PROFILE_ROLE-$PHASE.json"
```

Profile roles are `witness`, `mirror`, `auditor`, or `release`;
the launcher role for the last one is `upload-station`.
The receipt must identify the actual Linux tools executed inside that image.
A host receipt for a different native binary is not interchangeable.

Review the printed ceremony, identity, phase, and paths.
Profiles retain paths, not key bytes or grants. Fresh scoped grants arrive
separately when an upload is authorized.

## Phase 2 and recovery

Stage the complete authenticated closed Phase 1 transcript, beacon, seal,
commons, compiled R1CS, and signed Phase 2 initialization.
The participant run repeats the authoritative Phase 1 replay and Phase 2
initialization checks before generating randomness.
Do not issue a grant as a substitute for preparing these prerequisites.

The low-level `open --reviewed-retry` switch exists for maintainer-operated named
actions; it is not the guided workflow's recovery policy. Guided roles use
task-specific checks. For a participant, preserve the public candidate and use
the same profile's recovery/resume flow. Do not overwrite signed state.
