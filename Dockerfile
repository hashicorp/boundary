# Copyright IBM Corp. 2020, 2026
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
RUN setcap cap_ipc_lock=+ep /bin/boundary

RUN mkdir /boundary/
ADD .release/docker/config.hcl /boundary/config.hcl
RUN chown -R boundary:boundary /boundary/
RUN chmod -R 640 /boundary/*

EXPOSE 9200 9201 9202
VOLUME /boundary/

LABEL org.opencontainers.image.licenses="BUSL-1.1"

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
COPY bin/LICENSE.txt /usr/share/doc/boundary/LICENSE.txt

USER boundary
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
    setcap cap_ipc_lock=+ep /bin/boundary && \
    cp /bin/LICENSE.txt /usr/share/doc/boundary/LICENSE.txt && \
    mkdir /boundary

COPY .release/docker/config.hcl /boundary/config.hcl

RUN chown -R boundary:boundary /boundary/ 
RUN chmod -R 640 /boundary/*

EXPOSE 9200 9201 9202
VOLUME /boundary/

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER boundary
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
RUN setcap cap_ipc_lock=+ep /bin/$BIN_NAME

RUN chown -R ${NAME}:${NAME} /boundary
RUN chmod -R 640 /boundary/*

EXPOSE 9200 9201 9202
VOLUME /boundary/

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

USER ${NAME}
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config", "/boundary/config.hcl"]


## UBI DOCKERFILE ##
FROM registry.access.redhat.com/ubi9/ubi-minimal AS ubi

ARG BIN_NAME
# NAME and PRODUCT_VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=boundary PRODUCT_VERSION=0.18.0
ARG NAME=boundary
ARG PRODUCT_VERSION
ARG PRODUCT_REVISION
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH
# LICENSE_SOURCE is the path to the license file in the build context.
ARG LICENSE_SOURCE=LICENSE
# LICENSE_DEST is the path where the license file is installed in the container.
ARG LICENSE_DEST=/usr/share/doc/boundary

# Additional metadata labels used by container registries, platforms
# and certification scanners.
LABEL name="Boundary" \
      maintainer="Boundary Team <boundary@hashicorp.com>" \
      vendor="HashiCorp" \
      version=${PRODUCT_VERSION} \
      release=${PRODUCT_REVISION} \
      revision=${PRODUCT_REVISION} \
      summary="Boundary enables practitioners to apply fine-grained authorization policies to infrastructure." \
      description="Boundary enables practitioners to apply fine-grained authorization policies to infrastructure access, with a focus on identity-based access controls and usage visibility across dynamic infrastructure."

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME

# Copy the license file as per Legal requirement
COPY ${LICENSE_SOURCE} ${LICENSE_DEST}/

# We must have a copy of the license in this directory to comply with the HasLicense Redhat requirement
# Note the trailing slash on the first argument -- plain files meet the requirement but directories do not.
COPY ${LICENSE_SOURCE} /licenses/

# Set up certificates and base tools.
RUN set -eux; \
    microdnf install -y ca-certificates gnupg openssl libcap tzdata procps shadow-utils util-linux tar && \
    microdnf clean all && \
    rm -rf /var/cache/dnf /var/cache/yum

# Create a non-root user to run the software.
RUN groupadd --gid 1000 ${NAME} && \
    adduser --uid 1001 --system -g ${NAME} ${NAME} && \
    usermod -a -G root ${NAME}

# Copy in the new Boundary from CRT pipeline, rather than fetching it from our public releases.
COPY dist/${TARGETOS}/${TARGETARCH}/${BIN_NAME} /usr/local/bin/${BIN_NAME}

# Set IPC_LOCK at build time because the container runs as an unprivileged user
RUN setcap cap_ipc_lock=+ep /usr/local/bin/${BIN_NAME}

ENV HOME=/home/${NAME}
RUN mkdir -p /opt/boundary $HOME /usr/share/doc/boundary && \
    chown -R ${NAME} /opt/boundary $HOME && \
    chgrp -R 0 /opt/boundary $HOME /usr/local/bin/${BIN_NAME} /usr/share/doc/boundary && \
    chmod -R g+rwX /opt/boundary $HOME /usr/local/bin/${BIN_NAME} /usr/share/doc/boundary

COPY ./.release/docker/config.hcl /opt/boundary/config.hcl

COPY .release/docker/ubi-docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

WORKDIR /opt/boundary

USER ${NAME}

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config=/opt/boundary/config.hcl"]
