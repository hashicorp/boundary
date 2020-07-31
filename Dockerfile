FROM golang:1.14

RUN "git config --global url.ssh://git@github.com/.insteadOf https://github.com/"

WORKDIR /watchtower

COPY . .
