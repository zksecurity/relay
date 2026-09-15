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
