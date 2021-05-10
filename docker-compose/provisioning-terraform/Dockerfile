From hashicorp/terraform:light
COPY ./scripts /scripts
COPY ./wait-for.sh /wait-for.sh

RUN chmod +x /wait-for.sh
RUN terraform -chdir='/scripts' init
