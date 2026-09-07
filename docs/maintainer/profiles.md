# Prepare authenticated role profiles

This is the remaining manual setup step for the coordinator and role operator.
Guided setup saves an action; it does not invent ceremony inputs or authenticate
a role assignment by itself.

Stage the signed definition and signature under `CEREMONY_HOME/public`,
the storage config under `CEREMONY_HOME/config`, and mutable output under
`CEREMONY_HOME/run`. Keep the coordinator public key independently authenticated.

The coordinator must supply a matching tool-identity receipt and the exact
approved tool files. The native installer does not generate that receipt.
Legacy kit `setup verify --receipt-out FILE` emits one for the kit's tools;
do not reuse a receipt for different host or container binaries.

## Participant: host paths

Set absolute host paths for every variable below; select one phase per profile.
Stage the approved Linux proof-tool file at the same resolved absolute path
on the host and inside the image (normally `/usr/local/bin/mpc-ceremony`).
On a Mac the host hashes this Linux file; Docker executes it.

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
Production Mac participants must already appear in `host_wipe_participants`.
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

For an unfinished ordinary saved action, inspect outputs before
`open --reviewed-retry`. For a participant, preserve the public candidate and
use the same profile's recovery/resume flow. Do not overwrite signed state.
