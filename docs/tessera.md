# Prepare a setup for Tessera

This chapter describes the legacy v1 roster flow. New website drafts use the
[shared v2 setup](tessera-setup-v2.md).

Use a CLI release containing `tessera export-setup` and the matching installed
role images. Older releases do not support this workflow. Run
`relay tessera capabilities --json` to check support for `tessera-bundle-v1` and
`tessera-draft-context-v1`.

1. In Tessera, add the public identities and roles. The protocol requires exactly
   one coordinator, one release signer, at least two auditors, and participants
   for both phases. Roles need distinct identity IDs, key IDs, and public keys.
   Witness and mirror assignments are retained, but their separate protocol
   enrollment happens after the signed definition exists.
2. Save both phase orders and download the roster JSON.
3. Open the installed CLI's coordinator preparation menu (see
   [Prepare a ceremony](coordinator-setup.md)). Choose **Open setup
   downloaded from Tessera**, select the JSON, compare fingerprints with their
   owners, and confirm. This replaces the local draft's mode, identities, orders,
   and minimum counts. It does not generate or copy private signing keys.
4. Review **Basics** (including circuit) and the beacon policy. Supply your local
   coordinator key and the administrator's AWS storage settings. Review and
   initialize explicitly. These actions retain their normal local confirmations;
   production initialization can take substantial resources.
5. Once definition verification succeeds, choose **Export setup for Tessera**.
   Choose a fresh JSON output path. This verifies the definition again using the
   exact released image and exports only public artifacts and storage fields.
6. Import that JSON into Tessera, preview, review, and freeze. Publishing remains
   a separate action.

Changing roles or order locally after importing a roster blocks initialization.
Change the website draft, save, and import a fresh roster instead. Once local
initialization has been attempted, its signed settings cannot be changed. If the
website draft changes afterward, reconcile the drafts before proceeding; do not
delete or overwrite signed output to force a retry. Tessera rejects exports for a
different draft revision.

## Export an existing signed setup

The command is also available outside the menu:

```sh
relay tessera export-setup \
  --context roster.json \
  --ceremony /absolute/work/ceremony/public/ceremony.json \
  --ceremony-signature /absolute/work/ceremony/public/ceremony.sig \
  --coordinator-key-file /absolute/trust/setup-coordinator.hex \
  --release role-images-FULL_COMMIT \
  --storage-public storage-public.json \
  --out tessera-setup.json
```

`--platform linux/amd64` or `linux/arm64` selects the installed inspection image;
the default is the host architecture with Linux as the container OS. The exact
release map is downloaded and its GitHub attestation verified. The launcher must
match that commit. Docker inspection uses a read-only snapshot, no network, and
no private-key or credential mounts; it never pulls images. Install/preload the
release image first. There is no arbitrary binary or image override.

`storage-public.json` contains exactly these public fields:

```json
{
  "provider": "aws",
  "region": "us-east-1",
  "public_base_url": "https://ceremony.example.org",
  "published_bucket": "ceremony-public",
  "inbox_bucket": "ceremony-inbox"
}
```

Do not supply a credentials file. Unknown fields, URL credentials, duplicate
JSON keys, mismatched identities/orders/minima, unapproved proof-tool binaries,
and existing output paths are rejected. Original signed definition and signature
bytes are preserved. The embedded software manifest includes the authenticated
role-image map, this launcher's embedded proof-tool pins, and its actual role
workflow catalog. The catalog digest describes the pinned local workflow;
it does not prove that its steps or contributions have completed.

Tessera export does not implement participant handoff import or status-report
ingestion. Capabilities only advertises the file schemas supported by this build.
