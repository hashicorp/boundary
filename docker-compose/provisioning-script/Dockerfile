From  hashicorp/boundary:0.2.1

USER root

RUN apk update && apk add jq

COPY ./scripts /scripts
COPY ./wait-for.sh /wait-for.sh

RUN chown boundary:boundary /wait-for.sh
RUN chmod +x /wait-for.sh
RUN chown -R boundary:boundary /scripts
RUN chmod +x /scripts/*

USER boundary