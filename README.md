# Relay

Relay moves MPC ceremony artifacts between local machines and S3-compatible
storage. It asks proof-tool to authenticate ceremony state and contributions.

## Run your role

Start at the [documentation index](docs/README.md).
Install once, then follow the guide for your assigned role:
[coordinator](docs/roles/coordinator.md),
[participant](docs/roles/participant.md),
[witness](docs/roles/witness.md),
[mirror](docs/roles/mirror.md),
[auditor](docs/roles/auditor.md), or
[final-parameter signer](docs/roles/release-signer.md).

Each role guide explains its numbered helper, public-file handoffs, and recovery.
The coordinator supplies ceremony-specific public inputs and reviewed arguments.
Never send a role's private key to the coordinator or website.

## Verify a public ceremony

Anyone with the complete public ceremony ZIP can check its signed release,
contributions, final keys, and production GO decision. This does not require a
ceremony role, signing key, or AWS credentials:

```bash
relay verify-ceremony --archive /absolute/path/to/go-ceremony.zip
```

Use a released Relay executable with its pinned proof tool. On macOS, install
Docker Desktop and GitHub CLI: Relay authenticates its matching release image
and runs the Linux proof tool inside Docker. The check can take substantial time
and needs disk space to expand the archive. Inspect the JSON result for
`"passed": true` and compare its `ceremony_id` with an independently obtained
ceremony ID. A guided V5 archive does not require an official storage pointer,
so `"officially_published": false` does not by itself mean verification failed.

This verifies existing proof evidence; it does not create a new application
proof. See [public verification and publication](docs/tasks/upload.md) for the
optional official-publication check and its separate trust inputs.

## Develop and maintain

- [Maintainer reference](docs/maintainer/README.md)
- [Transport layout and developer CLI](docs/maintainer/transport.md)
- [Software releases](docs/maintainer/releases.md)
- [Tessera roster import and setup export](docs/tessera.md)
- [Shared website setup v2](docs/tessera-setup-v2.md)
- [Legacy three-machine rehearsal](scripts/three-machine-rehearsal/README.md)

Relay is written in Go; use the version in `go.mod`.
Run `go test ./...` for the ordinary suite.
Real Docker smoke tests are described in the [role image guide](docs/maintainer/role-images.md).
