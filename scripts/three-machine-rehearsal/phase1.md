# Legacy rehearsal: Phase 1

First finish [preparation](prepare.md). Continue with [Phase 2](phase2.md).

## Phase 1

### 1. Machine 1: configure storage

If the storage does not exist yet, run the provider setup first:

- Downloaded kit: `$S/docs/maintainer/aws.md` or `$S/docs/maintainer/r2-rehearsal.md`
- Source checkout: [AWS setup](../../docs/maintainer/aws.md) or
  [Cloudflare R2 setup](../../docs/maintainer/r2-rehearsal.md)

The provider scripts are in the same relative location in a source checkout
and in the extracted kit. Resolve that directory first:

```bash
STORAGE_SETUP_ROOT=$(realpath "$S/../storage-setup")
```

For AWS, pass the generated Machine 1 file to the setup command:

```bash
"$STORAGE_SETUP_ROOT/scripts/storage-setup/setup-aws.sh" --machine-env "$E"
```

The default file is
`$HOME/ceremony-tools/three-machine-rehearsal/machine-1/.env`, outside the
immutable downloaded `ceremony-kit` directory. AWS setup atomically populates
its non-secret storage fields; `STORAGE_ENDPOINT=` intentionally remains
empty. All secret credential values remain outside the file. Provider scripts
still print the resulting non-secret block for the operator log.

For R2, authenticate Wrangler and create the short-lived token manager described
in the provider guide, then pass the generated Machine 1 file to the wrapper:

```bash
TOKEN_MANAGER_FILE="$HOME/.config/relay/cloudflare-token-manager"
"$STORAGE_SETUP_ROOT/scripts/storage-setup/setup-r2-wrangler.sh" \
  --token-manager-file "$TOKEN_MANAGER_FILE" \
  --machine-env "$E"
```

The wrapper discovers the authenticated account and active Cloudflare zones,
generates the bucket names, provisions the resources, stores the inbox-parent
API token and Secret Access Key in separate protected local files, and
atomically populates the non-secret Machine 1 fields. Relay prefers the Secret
Access Key to sign temporary credentials locally. With no active zone it uses
a rate-limited, rehearsal-only `r2.dev` origin for the published bucket while
keeping the inbox private.
Cloudflare requires one account token to be created in its dashboard with
**Account > Account API Tokens > Edit**. The wrapper uses that short-lived
token to create the two differently scoped R2 credentials automatically. Revoke
the token manager and remove its local file as soon as setup succeeds. Without
it, the wrapper falls back to prompting for two manually created R2
credentials.

```bash
"$S/01-coordinator-configure-storage.sh" "$E"
```

For the recommended R2 rehearsal path, step 1 refreshes the current Wrangler
OAuth token only long enough to confirm that the inbox has neither public
`r2.dev` access nor an attached custom domain. Later grant and upload steps do
not require Wrangler. The OAuth value is not stored in the rehearsal `.env`.
The explicit-token production path instead uses a protected control-token file
with account-level `Workers R2 Storage Read`; Cloudflare does not offer
bucket-scoped configuration read, so use a dedicated ceremony account if that
scope is unacceptable.

For AWS, the guided setup uses one profile for both coordinator and issuer
operations, so Machine 1 sets both profile fields to the same name. Relay also
supports separate coordinator and issuer profiles when an organization needs
stricter privilege separation. Machine 1 also records both bucket names, the
published HTTPS origin, and the grant role name. The wrapper reads the region
and account ID through the selected AWS CLI profile, then derives the regional
S3 endpoint and full role ARN. It prints the resolved
values before Relay performs its disposable storage probes. It never lists
buckets or CloudFront distributions and never guesses which resources to use.
After configuration, later coordinator steps reload those resolved values from
`run/relay-storage.json` instead of repeating AWS discovery.

Privately copy the resulting `relay-storage.json` to `trust/relay-storage.json`
under `WORK_ROOT` on Machines 2 and 3. It contains no temporary role credential,
but do not use the public ceremony bucket as the handoff. Role machines read
the published bucket and anonymous HTTPS origin from this file rather than
repeating them in their `.env`; no long-lived reader profile is needed.

### 2. Machine 1: publish the initial Phase 1 head

```bash
"$S/02-coordinator-publish-initial.sh" "$E" phase1
```

### 3. Machine 1: issue the participant-01 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase1 participant-01 /secure/handoff/phase1-participant-01.grant.json
```

Privately copy the grant to Machine 2 with mode `0600`.

### 4. Machine 2: run participant-01

```bash
"$S/04-role-participate.sh" "$E" phase1 participant-01 /secure/handoff/phase1-participant-01.grant.json
```

The script prints the path of a manifest-key file. Copy that small file to
Machine 1 as `/secure/handoff/phase1-participant-01.manifest-key.txt`.

If a participant finishes computation but its upload is interrupted, the
script archives the completed candidate and prints a five-argument recovery
command. Machine 1 issues a replacement grant for the same phase and identity
using a fresh grant filename. Run the printed command on the participant
machine with that new grant and archived candidate directory. Relay verifies
the saved candidate and unchanged public head, then continues the same upload
without recomputing. The replacement grant's minimum remaining time only needs
to cover verification and upload.

### 5. Machine 1: accept participant-01

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase1 participant-01 /secure/handoff/phase1-participant-01.manifest-key.txt
```

### 6. Machine 1: issue the participant-02 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase1 participant-02 /secure/handoff/phase1-participant-02.grant.json
```

Privately copy the grant to Machine 3.

### 7. Machine 3: run participant-02

```bash
"$S/04-role-participate.sh" "$E" phase1 participant-02 /secure/handoff/phase1-participant-02.grant.json
```

Copy its manifest-key file to Machine 1 as
`/secure/handoff/phase1-participant-02.manifest-key.txt`.

### 8. Machine 1: accept participant-02

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase1 participant-02 /secure/handoff/phase1-participant-02.manifest-key.txt
```

### 9. Machine 1: issue the participant-03 grant

```bash
"$S/03-coordinator-issue-participant-grant.sh" "$E" phase1 participant-03 /secure/handoff/phase1-participant-03.grant.json
```

Privately copy the grant to Machine 2.

### 10. Machine 2: run participant-03

```bash
"$S/04-role-participate.sh" "$E" phase1 participant-03 /secure/handoff/phase1-participant-03.grant.json
```

Copy its manifest-key file to Machine 1 as
`/secure/handoff/phase1-participant-03.manifest-key.txt`.

### 11. Machine 1: accept participant-03

```bash
"$S/05-coordinator-accept-participant.sh" "$E" phase1 participant-03 /secure/handoff/phase1-participant-03.manifest-key.txt
```

### 12. Machine 1: close and publish Phase 1

```bash
"$S/06-coordinator-close-phase.sh" "$E" phase1
```

Do not run the beacon step yet.

### 13. Machine 2: witness-01 checks the closure notification

```bash
"$S/07-role-witness-watch.sh" "$E" phase1 witness-01
```

### 14. Machine 3: witness-02 checks the closure notification

```bash
"$S/07-role-witness-watch.sh" "$E" phase1 witness-02
```

### 15. Machine 1: wait for and record the Phase 1 beacon

```bash
"$S/08-coordinator-record-beacon.sh" "$E" phase1
```

This waits about seven minutes for the pinned round, records and seals Phase 1,
initializes Phase 2, and publishes its initial head. The extra two minutes give
both witness machines time to see the notification while the signed five-minute
lead still remains. `witness watch` does not itself create a signed witness
receipt; the optional fixture section tests that upload shape separately.
