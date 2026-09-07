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

Each role guide includes its commands, expected results, and recovery steps.
The coordinator supplies ceremony-specific public inputs and reviewed arguments.
Never send a role's private key to the coordinator or website.

## Develop and maintain

- [Maintainer reference](docs/maintainer/README.md)
- [Transport layout and developer CLI](docs/maintainer/transport.md)
- [Software releases](docs/maintainer/releases.md)
- [Legacy three-machine rehearsal](scripts/three-machine-rehearsal/README.md)

Relay is written in Go; use the version in `go.mod`.
Run `go test ./...` for the ordinary suite.
Real Docker smoke tests are described beside the [image sources](docker/roles/README.md).
