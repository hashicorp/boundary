From hashicorp/terraform:0.15.3

COPY ./scripts /scripts
COPY ./wait-for.sh /wait-for.sh

RUN chmod +x /wait-for.sh
RUN terraform -chdir='/scripts' init
