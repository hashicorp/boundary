#!/bin/bash

### requires protoc-gen-go v1.20.0 or later 
# upgrade with: go get -u github.com/protocolbuffers/protobuf-go/cmd/protoc-gen-go

set -e 
protoc  --go_out=paths=source_relative:. ./store/oplog.proto
# now, inject custom gorm tags using: 
protoc-go-inject-tag -input=store/oplog.pb.go
protoc  --go_out=paths=source_relative:. ./any/any.proto


protoc  --go_out=paths=source_relative:. ./oplog_test/oplog_test.proto
# now, inject custom gorm tags using: 
protoc-go-inject-tag -input=store/oplog.pb.go