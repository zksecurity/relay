# Onboarding model-checking pilot

This models one coordinator and one participant, from enrollment to a Phase 1
profile. It does not modify the CLI or your ceremony. Start by reviewing this
table, then examine the checker traces and the actual CLI transcript.

See [the planned history-aware extension](history-design.md) for coordinator
enrollment checks, stale results, and model-to-CLI sequence testing. That scope
is not yet implemented in this pilot or covered by its recorded results.

## Intended transitions

| Current state | Action/instruction | New state |
|---|---|---|
| Prior identity and definition setup complete | Sign enrollment | Public enrollment exists |
| Enrollment exists | Explain exact public folder and coordinator recipient | Sending instruction shown |
| Sending explained | Participant reports sending | Sender report only; receipt unknown |
| Storage absent | Ask coordinator for `relay-storage.json`; explain import | Request/instruction recorded |
| Request received | Coordinator prepares public storage settings | Coordinator has settings |
| Coordinator has settings | Deliver file | Participant has a received file, not yet imported |
| File received | Import | Local settings exist; previous verification invalidated |
| Correct settings imported | Create profile, validating inputs within the action | Profile bound to validated settings |
| Wrong settings imported | Request replacement | Creation not recommended |
| Reopen | Keep durable state; discard cached verification | Files and reported exchanges retained |

The model's `good` and `wrong` are symbolic artifact identities; verification
is abstracted, not a model of signatures or Groth16. Profile bindings refer to
the bytes used at creation, not a later replacement of the local file.

## Run it yourself

Requires Docker, Bash, curl and shasum. Downloads are test tools, not Relay
release assets. The script verifies the pinned jar SHA-256 and pins the Java
container digest. It mounts only this model and the jar, read-only, with no
network during checking. It retains temporary text logs.

```bash
cd /Users/jinseokpark/relay
MODEL_TOOLS=$(mktemp -d)
curl --fail --location --max-time 90 \
  -o "$MODEL_TOOLS/tla2tools.jar" \
  https://github.com/tlaplus/tlaplus/releases/download/v1.7.4/tla2tools.jar
./models/onboarding/check.sh "$MODEL_TOOLS/tla2tools.jar"
```

Four runs have different expected outcomes:

| Configuration | Expected result | What it establishes |
|---|---|---|
| `current.cfg` | `StorageBeforeRecommendation` violation | Current recommendation rule exposes the known missing-storage gap |
| `proposed.cfg` | No invariant violation | Proposed model satisfies four safety properties within this finite abstraction |
| `reach-success.cfg` | `NeverFinished` violation | A successful profile-creation path exists; the model does not simply block everything |
| `reach-send-only.cfg` | `NoUnacknowledgedSend` violation | Reporting an enrollment send can occur before coordinator receipt |

Coordinator receipt is a separate transition, not acceptance and not knowledge
at the participant. The pilot does not model an acknowledgment back to them.
Only exact expected invariant failures count; syntax errors or missing tools
are failures of the check script. `current` is a deliberately broken-rule
variant of `proposed`, providing a mutation/sensitivity check.

## Check the actual CLI

```bash
RELAY_MODEL_CONTRACT=1 go test ./cmd/relay \
  -run '^TestOnboardingModelContract$' -count=1 -v
```

This test now passes after the guidance fix: expect the coordinator storage
request and `Choose [3]`. The historical failure is retained in `results.md`.
It creates disposable synthetic presence fixtures,
opens the real menu, and exits without running cryptographic commands.
It tests the recommended next action, not whether option 4 is listed elsewhere.
Normal test runs now include this desired-contract regression.

## Scope and review

This is not an end-to-end role journey or a proof of the implementation.
The Go adapter checks one state, not every model trace. Instruction text
accuracy, receipt authentication/acceptance, multiple roles/turns, actual file authentication,
Tessera, cloud access, interrupted child operations and old-session migration
remain outside the pilot. Restart is an abstract action, not a real CLI restart
test. Instruction/report flags are assumed durable; files are not silently sent.

Deadlock checking is disabled; no liveness or absence of circular waiting is
claimed. Completion reachability is weaker than guaranteed eventual completion.
Cryptographic validation is assumed atomic for this narrow model.

Independent review tightened recommendation-vs-menu checking, allowed validation
inside profile creation, required exact expected failures, and added a
successful-path witness. Results are recorded in `results.md`.
