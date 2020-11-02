FROM docker.mirror.hashicorp.services/alpine:3.10

RUN addgroup boundary && \
    adduser -S -G boundary boundary

ADD bin/boundary /bin/boundary

RUN mkdir /boundary/
ADD docker/config.hcl /boundary/config.hcl
RUN chown -R boundary:boundary /boundary/ 

EXPOSE 9200 9201 9202
VOLUME /boundary/

USER boundary
ENTRYPOINT ["/bin/boundary"]
CMD ["server", "-config", "/boundary/config.hcl"]
