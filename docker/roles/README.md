# Role image sources and tests

Operators use [installation](../../docs/install.md) and their
[role guide](../../docs/README.md). CI builds and publishes production images;
see [release engineering](../../docs/maintainer/releases.md).

The Dockerfile builds an online image containing Relay, proof-tool, and AWS CLI,
and an offline image containing proof-tool. Contributor isolation uses
[the contributor Dockerfile](../ceremony-tool/Dockerfile).
Runtime controls and mounts are documented in the
[launcher reference](../../docs/maintainer/launcher.md).

## Local development builds

Stage only the reviewed Linux Relay/proof-tool binaries in `IMAGE_BUILD_ROOT`.
Never use a build context containing keys or credentials.
Pin the AWS CLI base image by repository digest.

```bash
docker build --platform "$LINUX_PLATFORM" --target online \
  --build-arg AWS_CLI_IMAGE="$AWS_CLI_IMAGE" \
  --file docker/roles/Dockerfile --tag ceremony-online:local "$IMAGE_BUILD_ROOT"
docker build --platform "$LINUX_PLATFORM" --target offline \
  --build-arg AWS_CLI_IMAGE="$AWS_CLI_IMAGE" \
  --file docker/roles/Dockerfile --tag ceremony-offline:local "$IMAGE_BUILD_ROOT"
```

Use full immutable image IDs from `docker image inspect` for local tests.
A local tag is not a production release approval.

## Real Docker tests

Run as a non-root operator with a local Docker daemon:

```bash
RELAY_ROLE_ONLINE_IMAGE="$ONLINE_IMAGE" \
RELAY_ROLE_OFFLINE_IMAGE="$OFFLINE_IMAGE" \
RELAY_ROLE_PLATFORM="$LINUX_PLATFORM" \
go test ./cmd/relay -run 'TestDockerRoleImages|TestGuidedDockerOpen' -count=1 -v
```

This checks all eight role presets, security settings, key generation, and a
saved guided action. It does not test a full two-phase ceremony or storage.

For the same-host tiny three-contribution Phase 1 test, additionally set
`RELAY_ROLE_REHEARSAL=1` and run `TestDockerRolesTinyPhase1Rehearsal`.
It tests contributor cleanup and coordinator acceptance, not independent roles,
object storage, Phase 2, or final release. Never use production keys in tests.
