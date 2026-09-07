# Try coordinator preparation locally

This developer harness uses a separate launcher and two local Docker images.
It leaves approved installations unchanged and performs no release publishing.
The local preparation entry point is absent from ordinary builds.

You need Go (the version selected by `go.mod`), Docker, jq, curl and shasum.
Run these commands yourself from the Relay checkout:

```sh
./scripts/local-coordinator.sh prepare "$HOME/ceremonies/local-coordinator-test"
./scripts/local-coordinator.sh run "$HOME/ceremonies/local-coordinator-test"
```

`prepare` asks before downloading pinned inputs and building local binaries/images.
It does not start the interactive helper or initialize a ceremony.
It requires a fresh folder and never overwrites an existing test setup.
Build contexts contain only binaries and the Dockerfile, never role keys.

`run` opens the same coordinator menu using the `relaylocal` development build.
It resumes the draft in that test folder. The local entry point only allows
the tiny rehearsal circuit, key generation and definition verification.
Cloud operations, contributions and extra binary allowlists are disabled.
These images are local test artifacts, not approved production releases.

## Suggested first pass

1. The harness supplies **mock public identities** for two auditors, a
   final-parameter signer and a participant. Their private keys are discarded;
   this is an initialization/UI test, not a complete multiparty ceremony.
2. Choose **2** to generate your test coordinator identity in Docker.
3. Choose **3**, role `coordinator`, and import
   `~/ceremonies/local-coordinator-test/keys/identity.json` using its full path.
   Confirm the displayed fingerprint. Do not import your production identity.
4. Choose **4** and accept the suggested template, participant orders and minimums.
5. Choose **7** to review, then **0** to exit. Run the second command again to
   confirm your draft was saved.
6. When ready, choose **8** and type `INITIALIZE REHEARSAL`.
   Review and confirm each displayed Docker command.
7. Successful initialization is followed by proof-tool signature verification.

Failed initialization remains frozen for investigation, as in the real helper.
Do not delete uncertain outputs to force a retry. Use a fresh, separately named
test folder for another independent experiment.

## Automated checks

```sh
go test ./cmd/relay -run TestOrdinaryBuildHasNoLocalCoordinator
go test -tags relaylocal ./cmd/relay -run TestLocalCoordinatorBoundaries
```

The opt-in `TestCoordinatorPrepareDocker` test covers real tiny initialization
and invalid-signature rejection; it takes `RELAY_PREPARE_TEST_IMAGE` as an
immutable local online-image ID.
