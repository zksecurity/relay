# Connect Cloudflare R2 storage — agreed helper design

Status: implementation and testing in progress; not released. Part of the
[guided ceremony journey](guided-journey-design.md).

The helper now supports existing-resource discovery, manual configuration,
hidden credential entry, dedicated file mounts and session-file cleanup.
Infrastructure and scoped-grant probes passed live R2 validation on 2026-09-08,
including the same temporary credential working before expiry and being rejected
after expiry while a fresh control grant still worked. Credential recovery, refreshed-login
handling and complete probe failure coverage still need release review.

## Entry and resource selection

Open from Set up storage or a missing-storage prerequisite. Return to the
interrupted task afterward, without requiring configuration paths or menu hopping.
Discover existing accounts/buckets using an available authorized login; ask the
user to confirm the account, published bucket, private inbox and public origin.
If discovery is unavailable, offer administrator settings or explicit selection.
Check for existing ceremony data and avoid conflicting publication locations.
Resource creation is separate and explicitly approved, including potential costs.

## Credential input

```text
CONNECT CLOUDFLARE R2
------------------------------------------------------------
1) Paste credentials
   From any password manager or the token-creation screen.

2) Use existing protected credential files

3) Show how to create the required credentials

0) Cancel
```

Ask only for missing credentials and explain their distinct purposes:
coordinator storage access, inbox-only temporary-grant issuance, and bucket
privacy inspection. Never ask for a Cloudflare account password or signing key.
Reuse an appropriate coordinator profile; explicitly authorize login use for
privacy inspection, with a separately scoped control credential as an alternative.
Do not require both the parent API token and its Secret Access Key when one
supported issuance method suffices. Never scrape a password manager or clipboard.
Use hidden secret entry with terminal echo restored on cancellation/interruption.
Validate format without printing values, including in errors, logs or telemetry.

## Storage and Docker delivery

Offer `1) Save in protected local files`, `2) Use for this session only`, and
`0) Cancel`. Explain that session-only use requires re-entry after closing.
Persistent credentials live outside work/public folders, in owner-only files
and directories. Save references, not values, in profiles and action history.
Require explicit replacement; preserve existing credentials on failed import.
Replacing a local credential does not revoke the old cloud token.
Reject unsafe file types/permissions and avoid symlink or replacement races.
Do not silently copy an entire unrelated credential store into a container.
Deliver only the operation's required credentials through restricted read-only
secret mounts and a reviewed in-container adapter. No Docker socket mount.
The adapter uses the existing CLI environment interface only inside the process;
secret values must not enter Docker's configured environment, command arguments,
saved actions, image layers, diagnostic output or ordinary work directories.
Session-only delivery must define transient storage and cleanup on success,
cancellation and interruption. Do not promise RAM-only storage or physical erasure;
disclose any temporary-file requirement before accepting that mode.

## Verification and return

Ask permission before temporary cloud probes; use isolated fresh object prefixes.
Check coordinator permissions, anonymous published access, inbox privacy and
temporary-grant restrictions, including required out-of-scope denials.
Do not equate a bucket read or a successful HTTP response with complete readiness.
Distinguish checks possible before initialization from signed-ceremony-dependent
checks afterward. Do not invent a signed ceremony merely to run infrastructure tests.
Label only completed checks Passed; unknown or failed checks remain visible.
Report probe cleanup failures and retain enough non-secret information to resolve.
Offer Replace credential, Retry check or Save and exit after an actionable error.
Save validated configuration automatically. Offer Review and initialize ceremony,
or Publish initial Phase 1 state for an already initialized ceremony, only when
that action's applicable checks pass. Never silently repeat initialization.

## Implementation review and tests

Before implementation, settle the adapter/file lifecycle and session-only threat
model, provider-specific scope probes, credential refresh and saved-flow migration.
Test both paste/file paths, no password-manager dependency, blank/invalid inputs,
safe replacement, expired credentials, login failure, isolated probe cleanup,
Docker inspection/log redaction, least-credential mounts, restart and cancellation.
Use fresh test resources with explicit approval for live validation; mocked tests
alone cannot establish actual cloud permissions or grant scope.
