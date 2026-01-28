# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

# This Dockerfile contains multiple targets.
# Use 'docker build --target=<name> .' to build one.
# e.g. `docker build --target=dev .`
#
# All non-dev targets have a VERSION argument that must be provided 
# via --build-arg=VERSION=<version> when building. 
# e.g. --build-arg=0.7.4
#
# `default` is the production docker image which cannot be built locally. 
# For local dev and testing purposes, please build and use the `dev` docker image.


# Development docker image
FROM docker.mirror.hashicorp.services/alpine:3.21 as dev

RUN set -eux && \
    addgroup boundary && \
    adduser -s /bin/sh -S -G boundary boundary && \
    apk add --no-cache wget ca-certificates dumb-init gnupg libcap openssl su-exec iputils libc6-compat iptables

ADD bin/boundary /bin/boundary

RUN mkdir /boundary/
ADD .release/docker/config.hcl /boundary/config.hcl
RUN chown -R boundary:boundary /boundary/
RUN chmod -R 640 /boundary/*

EXPOSE 9200 9201 9202
VOLUME /boundary/

LABEL org.opencontainers.image.licenses="BUSL-1.1"

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY bin/LICENSE.txt /usr/share/doc/boundary/LICENSE.txt

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config", "/boundary/config.hcl"]


# Official docker image that uses binaries from releases.hashicorp.com
FROM docker.mirror.hashicorp.services/alpine:3.21 as official

ARG PRODUCT_VERSION

LABEL name="Boundary" \
      maintainer="HashiCorp Boundary Team <boundary@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      summary="Boundary provides simple and secure access to hosts and services" \
      description="The Boundary Docker image is designed to enable practitioners to run Boundary in server mode on a container scheduler" \
      org.opencontainers.image.licenses="BUSL-1.1"

RUN set -eux && \
    addgroup boundary && \
    adduser -s /bin/sh -S -G boundary boundary && \
    apk add --no-cache wget ca-certificates dumb-init gnupg libcap openssl su-exec iputils libc6-compat iptables && \
    gpg --keyserver keyserver.ubuntu.com --recv-keys C874011F0AB405110D02105534365D9472D7468F && \
    cd /tmp && \
    apkArch="$(apk --print-arch)" && \
    case "${apkArch}" in \
        aarch64) boundaryArch='arm64' ;; \
        armhf) boundaryArch='armhfv6' ;; \
        x86) boundaryArch='386' ;; \
        x86_64) boundaryArch='amd64' ;; \
        *) echo >&2 "error: unsupported architecture: ${apkArch} (see https://releases.hashicorp.com/boundary/${PRODUCT_VERSION}/ )" && exit 1 ;; \
    esac && \
    wget https://releases.hashicorp.com/boundary/${PRODUCT_VERSION}/boundary_${PRODUCT_VERSION}_linux_${boundaryArch}.zip && \
    wget https://releases.hashicorp.com/boundary/${PRODUCT_VERSION}/boundary_${PRODUCT_VERSION}_SHA256SUMS && \
    wget https://releases.hashicorp.com/boundary/${PRODUCT_VERSION}/boundary_${PRODUCT_VERSION}_SHA256SUMS.sig && \
    gpg --batch --verify boundary_${PRODUCT_VERSION}_SHA256SUMS.sig boundary_${PRODUCT_VERSION}_SHA256SUMS && \
    grep boundary_${PRODUCT_VERSION}_linux_${boundaryArch}.zip boundary_${PRODUCT_VERSION}_SHA256SUMS | sha256sum -c && \
    unzip -d /bin boundary_${PRODUCT_VERSION}_linux_${boundaryArch}.zip && \
    rm boundary_${PRODUCT_VERSION}_linux_${boundaryArch}.zip boundary_${PRODUCT_VERSION}_SHA256SUMS boundary_${PRODUCT_VERSION}_SHA256SUMS.sig && \
    cp /bin/LICENSE.txt /usr/share/doc/boundary/LICENSE.txt && \
    mkdir /boundary

COPY .release/docker/config.hcl /boundary/config.hcl

RUN chown -R boundary:boundary /boundary/ 
RUN chmod -R 640 /boundary/*

EXPOSE 9200 9201 9202
VOLUME /boundary/

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config", "/boundary/config.hcl"]


# Production docker image
# Remember, this cannot be built locally
FROM docker.mirror.hashicorp.services/alpine:3.21 as default

ARG BIN_NAME
# NAME and PRODUCT_VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=boundary PRODUCT_VERSION=1.2.3.
ARG NAME=boundary
ARG PRODUCT_VERSION
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

LABEL name="Boundary" \
      maintainer="HashiCorp Boundary Team <boundary@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$PRODUCT_VERSION \
      release=$PRODUCT_VERSION \
      summary="Boundary provides simple and secure access to hosts and services" \
      description="The Boundary Docker image is designed to enable practitioners to run Boundary in server mode on a container scheduler" \
      org.opencontainers.image.licenses="BUSL-1.1"

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME
ENV VERSION=$PRODUCT_VERSION

# Create a non-root user to run the software.
RUN addgroup ${NAME} && adduser -s /bin/sh -S -G ${NAME} ${NAME}

RUN apk add --no-cache wget ca-certificates dumb-init gnupg libcap openssl su-exec iputils libc6-compat iptables

COPY .release/docker/config.hcl /boundary/config.hcl

COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/
COPY dist/$TARGETOS/$TARGETARCH/LICENSE.txt /usr/share/doc/boundary/LICENSE.txt

RUN chown -R ${NAME}:${NAME} /boundary
RUN chmod -R 640 /boundary/*

EXPOSE 9200 9201 9202
VOLUME /boundary/

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config", "/boundary/config.hcl"]
