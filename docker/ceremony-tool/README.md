# Ceremony-tool container image

This image is the disposable `mpc-ceremony` runtime used by Relay's Docker
participant driver. It contains only the statically linked Linux ceremony
binary. Relay supplies authenticated inputs as read-only mounts, disables the
network, and exposes one fresh public-output handoff.

For each allowed platform, copy its exact signed Linux binary into this
directory as `mpc-ceremony` and build the matching image:

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

Proof-tool v2 ceremonies may bind both the exact `linux/amd64` and
`linux/arm64` executables. Build and publish one immutable image per entry;
participants select their platform's image. Relay refuses an image platform
that has no matching signed binary. Legacy v1 ceremonies remain
single-platform.
