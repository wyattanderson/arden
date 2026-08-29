# syntax=docker/dockerfile:1

FROM golang:1.27-bookworm AS build

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        gcc \
        libkrb5-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
COPY auth ./auth
COPY ber ./ber
COPY protocol ./protocol
COPY rfc4511 ./rfc4511
COPY rfc4532 ./rfc4532
COPY *.go ./
COPY freeipa ./freeipa

WORKDIR /src/freeipa
RUN CGO_ENABLED=1 go build -tags=gssapi -trimpath -o /out/arden-freeipa-whoami ./cmd/whoami

FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
        ca-certificates \
        krb5-user \
        libgssapi-krb5-2 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 arden

COPY --from=build /out/arden-freeipa-whoami /usr/local/bin/arden-freeipa-whoami
COPY freeipa/krb5.conf /etc/krb5.conf
COPY freeipa/entrypoint.sh /usr/local/bin/entrypoint.sh

USER arden
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
