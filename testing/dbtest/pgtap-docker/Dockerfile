# Copyright IBM Corp. 2020, 2025
# SPDX-License-Identifier: BUSL-1.1

ARG PG_VERSION
FROM postgres:${PG_VERSION}-alpine

ARG PG_VERSION
ARG PGTAP_VERSION=v1.2.0

RUN echo 'http://dl-cdn.alpinelinux.org/alpine/v3.8/main'>> /etc/apk/repositories \
    && echo 'http://dl-cdn.alpinelinux.org/alpine/v3.6/main'>> /etc/apk/repositories \
    && apk add --no-cache --update curl wget git openssl \
      build-base make perl perl-dev

# install pg_prove
RUN PERL_MM_USE_DEFAULT=1 cpan -T TAP::Harness::JUnit \
  && PERL_MM_USE_DEFAULT=1 cpan -T TAP::Parser::SourceHandler::pgTAP

# install pgtap
RUN git clone https://github.com/theory/pgtap.git \
    && cd pgtap && git checkout tags/$PGTAP_VERSION \
    && make

COPY test.sh /test.sh
RUN chmod +x /test.sh

WORKDIR /

ENV DATABASE="" \
    HOST=db \
    PORT=5432 \
    USER="postgres" \
    PASSWORD="" \
    TESTS="/test/*.sql"

ENTRYPOINT ["/test.sh"]
CMD [""]
