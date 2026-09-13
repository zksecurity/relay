# Pilot results — 2026-09-13

## What to verify first

The model and the real CLI agree on this failure:

```text
Enrollment files become present locally.
No relay-storage.json has been imported.
CLI recommends: Authenticate the ceremony and create the Phase 1 profile.
Default answer: 4.

FAIL: StorageBeforeRecommendation / MODEL_CONTRACT_STORAGE
```

The initial pilot did not fix the CLI. The subsequent guidance implementation
now passes this contract test with `Choose [3]` and instructions to obtain the
coordinator's public storage file. The table below records the original pilot.

## Executed checks

| Check | Observed outcome |
|---|---|
| Current-rule model | Named invariant failure after 2 states, as expected |
| Proposed model | 33 distinct states explored; four safety invariants passed |
| Proposed completion witness | Profile creation reachable at trace depth 9 |
| Sender-report witness | Send reported before coordinator receipt at trace depth 4 |
| Actual CLI contract test | Failed with `MODEL_CONTRACT_STORAGE`, as expected for the unfixed CLI |
| Normal `go test ./...` | Passed; opt-in contract test skipped |
| `go vet ./...` | Passed |
| Shell syntax and diff whitespace | Passed |

TLC was the official v1.7.4 release jar (reports TLC2 2.19), checked against
the published release SHA-1 and then pinned by SHA-256 in `check.sh`.
One worker was used. The Java runtime ran in a disposable network-disabled
container; no Java runtime was installed on the Mac.

Complete model logs for this execution were retained locally at:
`/private/var/folders/0d/mh9gz6gn3q1_05wb9b_b3q700000gn/T/relay-model-check.mRZ1wD`.
Rerunning `check.sh` produces another directory with all four traces/results.

The actual CLI test prints its menu transcript with `-v`. It uses synthetic
presence fixtures and exits at the menu: this is not an authenticated ceremony
or a full model-to-CLI trace replay. No live ceremony files were touched.

## Interpretation

The checker is sensitive to the known recommendation bug, and the repaired
model allows progress. This establishes a useful pilot, not complete guidance
verification. The next implementation step would be to fix the actual CLI
recommendation and handoff/import instructions, then make the desired-contract
test pass and replay additional model transitions through real actions.

See `README.md` for the explicit limits, including no liveness proof and no
full-ceremony or cryptographic verification claim.
