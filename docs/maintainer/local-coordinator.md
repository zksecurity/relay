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
It resumes the draft in that test folder. Preparation only allows the tiny
rehearsal circuit, key generation and definition verification; it does not
configure cloud storage, contribute or add binary allowlists.
These images are local test artifacts, not approved production releases.

## Suggested first pass

1. New drafts start with an **empty roster**. Generate each test role separately:

   ```sh
   ./scripts/local-coordinator.sh identity "$HOME/ceremonies/local-coordinator-test"
   ```

   Repeat for one participant, one auditor, and a final-parameter signer.
   Each gets a separate folder under `test-roles` with its own private key.
   The generator prints the public `identity.json` path and fingerprint to share.
2. Choose **2** to generate your test coordinator identity in Docker.
3. Choose **3**, select **Coordinator** from the numbered role menu, and import
   `~/ceremonies/local-coordinator-test/keys/identity.json` using its full path.
   Confirm the displayed fingerprint. Do not import your production identity.
4. Choose **3** for each other role and import only its public identity file.
   Confirm the fingerprint shown by that role's generator. Nothing is auto-imported.
   Then choose **4** and review participant orders, minimums and the beacon template.
5. Choose **7** to review, then **0** to exit. Run the second command again to
   confirm your draft was saved.
6. When ready, choose **8** and type `INITIALIZE REHEARSAL`.
   Review and confirm each displayed Docker command.
7. Successful initialization is followed by proof-tool signature verification.
   Choose **12** to open the [remaining role workflow](../role-workflow.md).
   Other roles still need their own profiles and public files. Cloud transport
   needs separately provisioned rehearsal storage and a shared launcher profile
   with the rehearsal credentials; the local preparation profile has no credentials.

Failed initialization remains frozen for investigation, as in the real helper.
Do not delete uncertain outputs to force a retry. Use a fresh, separately named
test folder for another independent experiment.

## Existing tests with preloaded mocks

Exit the helper and rebuild your local launcher after updating the source.
For an unsigned draft, remove old mock assignments without deleting any files:

```sh
./scripts/local-coordinator.sh clear-mocks "$HOME/ceremonies/local-coordinator-test"
```

This asks for confirmation and preserves your coordinator identity and real
imports. It resets phase orders that referred to removed mocks; review them
after importing the new test identities. It refuses to change a frozen draft.
All roles here still belong to you on one machine, so this tests file handoff
and key separation—not independent participants or organizations.

## Automated checks

```sh
go test ./cmd/relay -run TestOrdinaryBuildHasNoLocalCoordinator
go test -tags relaylocal ./cmd/relay -run TestLocalCoordinatorBoundaries
```

The opt-in `TestCoordinatorPrepareDocker` test covers real tiny initialization
and invalid-signature rejection; it takes `RELAY_PREPARE_TEST_IMAGE` as an
immutable local online-image ID.
For the full tiny Docker ceremony lane and its limitations, see the
[workflow review and test scope](role-workflow-review.md).
