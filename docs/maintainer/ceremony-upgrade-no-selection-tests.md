# Ordinary use without an upgrade

Comparison baseline: main `5f1d3b10df50b26176f4a82565201c2e52c310ce`.
PR #67 is rebased onto that baseline, preserving its offline release-signing
and standalone AWS-renewal changes.

## Focused comparison

`TestNeverUpgradedDialogueComparison` runs the same menu functions on main and
the candidate. Its 46 comparisons cover all seven public roles:

- New and prepared role menus, folder instructions, saved drafts and reopening.
- Existing identity review, role profiles and child-command arguments.
- Coordinator draft and definition-verified menus and saved drafts.

The checked-in digest baseline normalizes fixture roots and synthetic hexadecimal
keys. It does not normalize ordinary wording, menu choices or command flags.
Child commands are captured, not executed. This is not full interactive ceremony
coverage. Runtime identity has separate exact-value assertions.

`TestNeverUpgradedEntryPointsAndSavedImages` checks all seven roles plus the
internal signing/key-generation profiles: no selection means unchanged profiles,
no extra setup files, original images for existing actions, and explicit original
image/platform pins for newly saved actions.

Run both with:

```sh
go test ./cmd/relay -run '^TestNeverUpgraded' -count=1
```

## Executed manual boundary check

Native executables built from main and the rebased candidate were used against
one isolated, non-upgraded saved coordinator profile:

1. Main prepared and ran an AWS-version action in Docker.
2. The candidate reopened that action and ran the same image and command.
3. The candidate saved a new action with explicit image/platform.
4. Main reopened and ran that new action successfully.

The prompts and AWS-version output matched. No credentials or ceremony secrets
were used; this tests Docker dispatch, not AWS permissions or cryptographic work.
Both worktrees' full Go suites, candidate vet and installer tests passed.
Live S3/R2 and the exact published-pair upgrade qualification are separate tests;
these results do not enable an upgrade pair or prove every possible workflow.
