# Website setup files

The v2 flow uses a single `ceremony-setup-v2` file. The coordinator chooses the
circuit, approved beacon profile, exact software release, public storage, signing
identities and contribution orders in Tessera before downloading it.

In the coordinator setup menu, choose **Open setup downloaded from Tessera**.
The CLI authenticates its matching release map, displays the public settings and
fingerprints, and asks for `IMPORT SETUP`. Private key and credential paths remain
local. Review the draft and explicitly approve initialization as usual. Changing
public settings locally causes initialization/export to fail; edit the website
plan and reopen its updated download before initialization.

After definition verification, **Export setup for Tessera** adds the authenticated
result. Import it on the website, review the saved result and recorded owners,
then explicitly freeze. Importing does not freeze or publish the ceremony.

A file with a result is review-only when opened: the CLI verifies its signed
definition and software without initializing or signing again. An initialized or
interrupted local workspace must be preserved; downloading another copy is not
permission to restart it. Witness/mirror protocol enrollment remains separate.

For explicit file-based operation:

```sh
relay tessera complete-setup --setup downloaded.json \
  --ceremony ceremony.json --ceremony-signature ceremony.sig \
  --coordinator-key-file coordinator-public-key.hex --out completed.json
relay tessera verify-setup --setup completed.json
```

The commands verify using the approved, preloaded Linux role image with no network,
private mounts or credentials. Install the exact matching launcher and role images
first. Output files are create-only. `--trusted-manifest` is intended for a server
administrator's independently attested local release catalogue; it is not an
alternative for trusting a manifest supplied in an uploaded setup.

Protected-main releases now publish and attest
`ceremony-software-manifest-v2.json`. The release contains the image map, pinned
proof-tool inputs, compiled workflow recipe, ruleset and schema digest before any
website plan selects it. Legacy v1 export and consent readers remain available.

Validation:

```sh
go test ./...
go vet ./...
TESSERA_PROOF_TOOL_BINARY=/path/to/approved/mpc-ceremony \
  TESSERA_TEST_OUTPUT_V2=/fresh/path/signed-fixture.json \
  go test ./cmd/relay -run '^TestSetupV2RealSignedRoundtrip$' -count=1
```

The optional test creates local rehearsal keys, initializes the exact website
beacon profile and checks real signatures. Its software image map is synthetic
test metadata; its output is not an approved release or production ceremony.

## Completed ceremony verification

The separate [public verification archive](../contracts/verification/v1/README.md)
packages complete protocol evidence after setup. `relay verify-ceremony --archive FILE`
checks the archive using the approved installed proof tool, including unsigned full
replay. It does not change the setup-v2 format or permit new software for old frozen
ceremonies. `relay pack-ceremony` prepares an explicit inventory of public files without
collecting a participant workspace or publishing it.

## Automatic Tessera storage access

After opening the website setup, Storage settings offers **Connect to Tessera
(automatic AWS renewal)**. Download the private CLI connection JSON from the
ceremony owner's Tessera page, protect it with chmod 600, then select that file.
Review the HTTPS origin, ceremony, coordinator fingerprint and expiry, and type
CONNECT TESSERA. The connection must match the imported ceremony, signing key,
and storage. No signing key is uploaded or replaced.

The CLI writes a dedicated mode-0600 AWS credential-process profile. For existing
Tessera temporary credentials it explicitly replaces that dedicated file at its
existing path so saved actions still work; unrelated AWS profiles are refused.
The connection token remains local and is never part of public setup exports.

AWS invokes the internal tessera storage-credentials command inside the trusted
online role image. This command sends its bearer token only to the reviewed HTTPS
origin, refuses redirects, and emits the AWS credential-process JSON on stdout.
Do not invoke this internal command to display credentials in a terminal or log.
Offline actions still receive no credentials mount.

Tessera checks current access on every request, including cached AWS credentials.
Connections expire after 30 days and can be disconnected on the website; existing
AWS credentials may remain valid for up to an hour. Download/import a new
connection after expiry or disconnection. Parent AWS login failures are reported
without discarding the local ceremony workspace. Old CLI releases retain manual
storage settings and one-hour credential files; never change a frozen release
pin just to enable this feature.

## Guided handoff update (unreleased)

After coordinator enrollment files are present, a Tessera-linked draft recommends
**Export setup for Tessera** instead of entering operations. A successful export
records its local absolute path and digest. On resume, an unchanged, present file
shows a return-to-Tessera checkpoint with **Save and exit**, **Export again**, and
explicit **Continue to ceremony operations**. Missing or changed exported files
recommend exporting again; exports use fresh paths and never overwrite an earlier
file. This local receipt is not proof of enrollment validity, website import,
review, locking, or publication. Operations retain their evidence checks.

Setup import distinguishes the private CLI connection schema and directs it to
Storage settings. Public-identity handoff text describes the Tessera invitation
upload path while retaining the standalone private-channel path.

Enrollment offers editable public-disclosure templates for shared operators,
shared organizations/equipment, no known shared signing operation, and custom
text. All choices are available in rehearsal and production. Required details
must be supplied; the exact statement is reviewed before public disclosure and
again with each enrollment's signed bytes. Existing enrollment records remain
immutable on resume, and their signatures are reverified. A preset neither proves
independence nor waives production role-separation requirements. Coordinator
output says to retain its public enrollment rather than send it to itself.

These menu changes require a new compatible release before existing installations
can use them. Existing ceremony release pins are not automatically upgraded.

## Role minimums: ruleset revision 2 (unreleased)

`contracts/setupv2r2/` defines `two-phase-v2` version 2: at least one auditor,
one witness per phase and one mirror per accepted contribution, in both modes.
Production still requires two participants per phase. All signature, identity,
independence and explicitly higher witness-quorum checks remain in force. The
release-signing menu requires one audit pair and allows additional signed reports.

The original `contracts/setupv2/` bytes are retained. Older ceremonies use their
original pinned CLI and proof-tool; no automatic conversion is supported. Release
order is proof-tool, then update real proof-tool pins and release the CLI, then
provision its attested manifest in Tessera and choose it as the default for new
ceremonies. Current `release/role-images.json` pins have not yet changed.
