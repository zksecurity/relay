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
