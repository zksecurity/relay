# Coordinator

Use this page as your live checklist. You schedule turns, verify submissions,
and publish accepted ceremony state. You do not hold other roles' private keys.

## Prepare once

- [ ] Complete [installation](../install.md) and retain the release identifier.
- [ ] Agree on the circuit, production/rehearsal mode, participant order,
      auditors, witnesses, mirrors, final-parameter signer, and emergency contact.
- [ ] Agree on an authenticated channel independent of ceremony storage.
- [ ] Collect public identities only; confirm fingerprints with their owners.
      Distinct keys are enforced; independent people and organizations are not.
- [ ] Explain the Docker cleanup precautions and remaining host/VM storage
      risk to participants before they begin; whole-machine wiping is optional.

Create your identity on your own machine. Set `IDENTITY_ID` and
`DISPLAY_NAME` to your agreed public values; use the directories from installation:

```bash
"$RELAY" ceremony setup coordinator-identity --role keygen \
  --release "$RELAY_RELEASE" --work "$ROLE_KEYS" -- \
  mpc-ceremony identity generate --identity-id "$IDENTITY_ID" \
  --display-name "$DISPLAY_NAME" --private-key-out /work/signing.hex \
  --public-identity-out /work/identity.json
"$RELAY" ceremony open coordinator-identity --role keygen
```

Success creates `signing.hex` and `identity.json` in `ROLE_KEYS`.
Share only the public JSON. Never share the private file.

## Initialize the ceremony and storage

- [ ] Obtain the release-specific proof-tool initialization recipe and reviewed
      circuit/roster/policy inputs. Execute it in the coordinator image.
      There is no automatic roster-to-ceremony wizard yet.
- [ ] Check the signed definition's circuit, identities, order, two-or-more
      auditors, distinct final-parameter signer, software allowlist, and beacon policy.
- [ ] Return the signed public definition to every role for assignment review.
- [ ] Collect signed witness/mirror enrollments after initialization; they bind
      to this exact definition. Obtain other enrollment records before grants.
- [ ] Have the storage administrator provision [AWS](../maintainer/aws.md)
      or [R2](../maintainer/r2.md), then run storage preflight.
      Provisioning can incur costs and still needs host tools.
- [ ] Require anonymous published reads, a private inbox, fresh public
      `state/*` reads, and prefix-limited temporary grants.

Use dedicated working, public-trust, key, and credential paths.
Inside the container these are `/work`, `/trust`, `/keys`, and
`/credentials/aws`. Stage `/work/ceremony/config/relay-storage.json`.
The credentials file must contain the profile named by that storage config.

For each command below, use a new action name. This helper saves and opens it:

```bash
coord() {
  local action="$1"; shift
  "$RELAY" ceremony setup "$action" --role coordinator \
    --release "$RELAY_RELEASE" --work "$ROLE_WORK" --trust "$ROLE_TRUST" \
    --keys "$ROLE_KEYS" --aws-credentials "$AWS_CREDENTIALS" -- "$@" &&
  "$RELAY" ceremony open "$action" --role coordinator
}
STORAGE=/work/ceremony/config/relay-storage.json
```

Review the displayed command before confirming. For initialization before
storage credentials exist, omit `--aws-credentials` from the setup command.
R2 control/parent secrets need the administrator's
[credential handoff](../maintainer/r2.md); the launcher does not forward host
environment secrets automatically.

## Repeat for each participant turn

Before the first turn on AWS, create the storage config after provisioning.
Set the public resource values from the administrator's output:

```bash
coord storage-preflight relay coordinator configure-storage \
  --home /work/ceremony --provider aws --region "$AWS_REGION" \
  --published-bucket "$PUBLISHED_BUCKET" --published-base-url "$PUBLISHED_BASE_URL" \
  --inbox-bucket "$INBOX_BUCKET" --profile "$AWS_PROFILE" \
  --issuer-profile "$ISSUER_PROFILE" --grant-role-arn "$GRANT_ROLE_ARN" \
  --grant-role-max-ttl "$GRANT_ROLE_MAX_TTL" \
  --coordinator-key /trust/coordinator-public-key.hex --out "$STORAGE"
```

Success completes the public/private storage probes and writes a fresh config.
Do not proceed after a failed privacy, freshness, or credential-scope check.

- [ ] Verify the signed head and confirm who is next. Do not overlap turns.
- [ ] Set `PARTICIPANT_ID`, `PHASE`, a fresh `ACTION` name, and a grant lifetime
      sufficient for replay, computation, and upload within provider limits.

```bash
coord "$ACTION-grant" relay coordinator grant --storage "$STORAGE" \
  --role participant --identity "$PARTICIPANT_ID" \
  --credential-ttl "$CREDENTIAL_TTL" --minimum-remaining "$MINIMUM_REMAINING" \
  --out "/work/ceremony/run/$ACTION.grant.json"
```

- [ ] Privately deliver that file only to the named participant.
- [ ] Wait for their candidate manifest key; list candidates if needed:

```bash
coord "$ACTION-list" relay coordinator candidates --storage "$STORAGE" --phase "$PHASE"
coord "$ACTION-accept" relay coordinator accept --storage "$STORAGE" \
  --candidate-key "$CANDIDATE_KEY" --coordinator-signing-key /keys/signing.hex \
  --verify-publish
```

A listing is only a discovery result. Acceptance verifies the actual candidate.
Success reports an advanced published head; independently authenticate it
before notifying the next participant. There is no separate post-wipe gate.

## Close phases and collect evidence

- [ ] Use the pinned proof-tool recipe to close the phase, collect independent
      pre-beacon observations, authenticate the agreed beacon, seal Phase 1,
      and initialize Phase 2. Do not substitute a beacon or reorder these steps.
- [ ] Publish each signed transition with the command below.
      Add `--closed` only when publishing a closed phase.

```bash
coord "$ACTION-publish" relay coordinator publish --storage "$STORAGE" \
  --chain "$CHAIN" --chain-signature "$CHAIN_SIGNATURE" --verify
```

- [ ] Issue role-scoped evidence grants only after authenticating the enrollment.
      Use `--role`, `--identity`, `--enrollment`, and
      `--enrollment-signature` with the grant command above.
- [ ] Discover evidence, download it into fresh review directories, and run
      the evidence-specific proof-tool verification before accepting it:

```bash
coord "$ACTION-evidence" relay coordinator evidence --storage "$STORAGE"
```

- [ ] Have independent auditors replay both phases from independent sources.
- [ ] Give the final-parameter signer the exact candidate, audits, and evidence.
- [ ] Verify final release/decision signatures, record authorization, and
      preserve the complete transcript and evidence on the required mirrors.
- [ ] Verify the archive before retiring grants or storage access.

## If something fails

Pause the affected turn; preserve public outputs and secret-free error logs.
Inspect signed local and public heads before retrying acceptance or publication:
the previous command may already have advanced the ceremony.
For leaked keys or grants, contain and revoke access, then agree on recovery.
Never edit signed files, delete high-water state, or relax validation to continue.
A failed ordinary saved action needs review before `open --reviewed-retry`.
