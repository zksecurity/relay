# syntax=docker/dockerfile:1
# Build with a statically linked Linux mpc-ceremony binary in this directory.
# The runtime image deliberately contains no shell, package manager, or network
# tooling. Relay overrides USER with the participant's non-root host uid/gid so
# read-only bind-mounted key files remain readable without weakening their mode.
FROM scratch

COPY --chmod=0555 mpc-ceremony /usr/local/bin/mpc-ceremony

USER 65532:65532
ENTRYPOINT ["/usr/local/bin/mpc-ceremony"]
