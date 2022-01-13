FROM docker.mirror.hashicorp.services/alpine:3.13.6 as default

ARG BIN_NAME
# NAME and VERSION are the name of the software in releases.hashicorp.com
# and the version to download. Example: NAME=boundary VERSION=1.2.3.
ARG NAME=boundary
ARG VERSION
# TARGETARCH and TARGETOS are set automatically when --platform is provided.
ARG TARGETOS TARGETARCH

LABEL name="Boundary" \
      maintainer="HashiCorp Boundary Team <boundary@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$VERSION \
      release=$VERSION \
      summary="Boundary provides simple and secure access to hosts and services" \
      description="The Boundary Docker image is designed to enable practitioners to run Boundary in server mode on a container scheduler"

# Set ARGs as ENV so that they can be used in ENTRYPOINT/CMD
ENV NAME=$NAME
ENV VERSION=$VERSION

# Create a non-root user to run the software.
RUN addgroup ${NAME} && adduser -s /bin/sh -S -G ${NAME} ${NAME}

RUN apk add --no-cache wget ca-certificates dumb-init gnupg libcap openssl su-exec iputils libc6-compat iptables && \
    mkdir /boundary

COPY docker/config.hcl /boundary/config.hcl

# COPY /$BIN_NAME/ /bin/
COPY dist/$TARGETOS/$TARGETARCH/$BIN_NAME /bin/

RUN chown -R ${NAME}:${NAME} /boundary

EXPOSE 9200 9201 9202
VOLUME /boundary/

COPY .release/docker/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config", "/boundary/config.hcl"]