# Ceremony-tool container image

This image is the disposable `mpc-ceremony` runtime used by Relay's Docker
participant driver. It contains only the statically linked Linux ceremony
binary. Relay supplies authenticated inputs as read-only mounts, disables the
network, and exposes one fresh public-output handoff.

Build the exact Linux binary selected by the signed ceremony definition, copy
it into this directory as `mpc-ceremony`, and build only the selected platform:

```sh
docker build --platform linux/amd64 \
  --tag ceremony-tool:VERSION \
  docker/ceremony-tool
```

For local rehearsal, obtain the immutable image ID:

```sh
docker image inspect ceremony-tool:VERSION --format '{{.Id}}'
```

For distributed use, publish the image and use its repository digest, such as
`registry.example/ceremony-tool@sha256:...`. Never put a mutable tag in a Relay
participant profile.

The ceremony currently binds one exact `mpc-ceremony` executable, including
its GOOS, GOARCH, and SHA-256. Therefore all participants in one ceremony must
use the image platform selected when that definition was created. This is a
current proof-tool software-binding constraint, not a Groth16 requirement. A
future multi-platform ceremony requires the signed definition and contribution
attestations to support an reviewed allowlist of equivalent binaries.
