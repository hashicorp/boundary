FROM golang:1.14

WORKDIR /go/src/boundary
COPY . .

RUN go install -v cmd/boundary/main.go
RUN cp /go/bin/main /go/bin/boundary

ENTRYPOINT ["boundary"]
