FROM docker.mirror.hashicorp.services/alpine:3.13.6

RUN set -eux && \
    addgroup boundary && \
    adduser -s /bin/sh -S -G boundary boundary && \
    apk add --no-cache wget ca-certificates dumb-init gnupg libcap openssl su-exec iputils libc6-compat iptables

ADD bin/boundary /bin/boundary

RUN mkdir /boundary/
ADD ./config.hcl /boundary/config.hcl
RUN chown -R boundary:boundary /boundary/

EXPOSE 9200 9201 9202
VOLUME /boundary/

COPY ./docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["server", "-config", "/boundary/config.hcl"]
