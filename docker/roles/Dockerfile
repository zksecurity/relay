# syntax=docker/dockerfile:1
# Supply a coordinator-approved AWS CLI image pinned by digest when building
# the online target. No package downloads or source builds happen here.
ARG AWS_CLI_IMAGE
FROM scratch AS offline
COPY --chmod=0555 mpc-ceremony /usr/local/bin/mpc-ceremony
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/mpc-ceremony"]

FROM ${AWS_CLI_IMAGE} AS online
COPY --chmod=0555 relay /usr/local/bin/relay
COPY --chmod=0555 mpc-ceremony /usr/local/bin/mpc-ceremony
ENV AWS_EC2_METADATA_DISABLED=true AWS_PAGER=""
USER 65532:65532
WORKDIR /work
ENTRYPOINT ["/usr/local/bin/relay"]
