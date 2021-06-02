FROM docker.mirror.hashicorp.services/alpine:3.10

ARG VERSION=0.2.3

LABEL name="Boundary" \
      maintainer="HashiCorp Boundary Team <boundary@hashicorp.com>" \
      vendor="HashiCorp" \
      version=$VERSION \
      release=$VERSION \
      summary="Boundary provides simple and secure access to hosts and services" \
      description="The Boundary Docker image is designed to enable practitioners to run Boundary in server mode on a container scheduler"

RUN addgroup boundary && \
    adduser -s /bin/sh -S -G boundary boundary

ADD https://releases.hashicorp.com/boundary/${VERSION}/boundary_${VERSION}_linux_amd64.zip /tmp/
ADD https://releases.hashicorp.com/boundary/${VERSION}/boundary_${VERSION}_SHA256SUMS /tmp/
ADD https://releases.hashicorp.com/boundary/${VERSION}/boundary_${VERSION}_SHA256SUMS.sig /tmp/ 

RUN apk add --no-cache ca-certificates gnupg openssl libcap su-exec dumb-init tzdata 
RUN cd /tmp/ && \
    BUILD_GPGKEY=C874011F0AB405110D02105534365D9472D7468F; \
    found=''; \
    for server in \
        hkp://p80.pool.sks-keyservers.net:80 \
        hkp://keyserver.ubuntu.com:80 \
        hkp://pgp.mit.edu:80 \
    ; do \
        echo "Fetching GPG key $BUILD_GPGKEY from $server"; \
        gpg --keyserver "$server" --recv-keys "$BUILD_GPGKEY" && found=yes && break; \
    done; \
    test -z "$found" && echo >&2 "error: failed to fetch GPG key $BUILD_GPGKEY" && exit 1; \
    gpg --batch --verify boundary_${VERSION}_SHA256SUMS.sig boundary_${VERSION}_SHA256SUMS && \
    grep boundary_${VERSION}_linux_amd64.zip boundary_${VERSION}_SHA256SUMS | sha256sum -c && \
    unzip -d /bin boundary_${VERSION}_linux_amd64.zip

RUN mkdir /boundary/
ADD config.hcl /boundary/config.hcl
RUN chown -R boundary:boundary /boundary/ 

EXPOSE 9200 9201 9202
VOLUME /boundary/

USER boundary
ENTRYPOINT ["/bin/boundary"]
CMD ["server", "-config", "/boundary/config.hcl"]
