FROM docker.mirror.hashicorp.services/alpine:3.13.6

ARG VERSION=0.8.0

LABEL name="Boundary" \
      maintainer="HashiCorp Boundary Team <boundary@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$VERSION \
      release=$VERSION \
      summary="Boundary provides simple and secure access to hosts and services" \
      description="The Boundary Docker image is designed to enable practitioners to run Boundary in server mode on a container scheduler"

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
        *) echo >&2 "error: unsupported architecture: ${apkArch} (see https://releases.hashicorp.com/boundary/${VERSION}/ )" && exit 1 ;; \
    esac && \
    wget https://releases.hashicorp.com/boundary/${VERSION}/boundary_${VERSION}_linux_${boundaryArch}.zip && \
    wget https://releases.hashicorp.com/boundary/${VERSION}/boundary_${VERSION}_SHA256SUMS && \
    wget https://releases.hashicorp.com/boundary/${VERSION}/boundary_${VERSION}_SHA256SUMS.sig && \
    gpg --batch --verify boundary_${VERSION}_SHA256SUMS.sig boundary_${VERSION}_SHA256SUMS && \
    grep boundary_${VERSION}_linux_${boundaryArch}.zip boundary_${VERSION}_SHA256SUMS | sha256sum -c && \
    unzip -d /bin boundary_${VERSION}_linux_${boundaryArch}.zip && \
    rm boundary_${VERSION}_linux_${boundaryArch}.zip boundary_${VERSION}_SHA256SUMS boundary_${VERSION}_SHA256SUMS.sig && \
    mkdir /boundary

COPY config.hcl /boundary/config.hcl

RUN chown -R boundary:boundary /boundary/ 

EXPOSE 9200 9201 9202
VOLUME /boundary/

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config", "/boundary/config.hcl"]