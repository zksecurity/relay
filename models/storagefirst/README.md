# Storage-first ceremony model

`Phase1Turn.tla` models the first implementation slice: one participant's
Phase 1 turn. It deliberately separates public checkpoint state from private
local state. A restart changes neither.

The model checks that:

- the mutable root names an immutable checkpoint that already exists;
- each public stage has one sequence number and advances in order;
- a participant cannot compute before its receipt is accepted;
- a coordinator cannot record acceptance before upload; and
- receipt and candidate attempt names are allocated before the role uses them.

Run it with a local TLA+ installation:

```sh
java -cp /path/to/tla2tools.jar tlc2.TLC -config phase1.cfg Phase1Turn.tla
```

This model is a protocol check, not an implementation test. Relay tests must
also execute the same boundaries against its real next-action evaluator and
proof-tool's transition verifier.

## Delivery retries under the revised trust model

`DeliveryRetries.tla` models one candidate-delivery slot after receipt
acceptance. Results represent complete, attempt-independent inventories, not
only the contribution binary. It distinguishes private uploaded bytes from
the coordinator's retained dispositions. Restart changes neither.

- `delivery-retries.cfg`: bounded history, one active allocation, rejected
  results cannot be accepted, acceptance is terminal, and every active
  allocation can be retired without creating a replacement.
- `delivery-limit-bug.cfg`: reproduces the reviewed bug where requiring a
  replacement prevents retirement at the history limit. Expected counterexample:
  `ActiveCanRetire`.
- `delivery-reach-acceptance.cfg`: checks that acceptance remains reachable,
  avoiding a vacuous safety result. Expected counterexample: `NeverAccepted`.

Use the same TLC command with the selected config and `DeliveryRetries.tla`.
The small bound (3) explores branching; production protocol limits remain
separate. This is not a cryptographic model, network-provider test, or proof of
automatic progress. The implementation correspondence is proof-tool's
`AllocateDeliveryV2`, `AdvanceDeliveryV2`, and
`ValidateCheckpointTransitionV4`, with regression tests for actual history
limits and signed minimum checks before closure. The original Phase 1 model
does not yet describe the whole new role journey.

Checked September 16, 2026 with TLC 2.19 (jar SHA-256
`936a262061c914694dfd669a543be24573c45d5aa0ff20a8b96b23d01e050e88`):
the corrected model explored 291 distinct states with no invariant failure.
The old mandatory-replacement model produced the expected retirement failure
at the third allocation. The reachability run produced the expected accepted
result after allocation and delivery. These results cover only the stated model.
