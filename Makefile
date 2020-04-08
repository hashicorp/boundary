# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))


### oplog requires protoc-gen-go v1.20.0 or later 	
# GO111MODULE=on go get -u google.golang.org/protobuf/cmd/protoc-gen-go@v1.20.1
proto:
	protoc  --go_out=paths=source_relative:. ./internal/oplog/any_operation.proto
	protoc  --go_out=paths=source_relative:. ./internal/oplog/store/oplog.proto
	protoc-go-inject-tag -input=./internal/oplog/store/oplog.pb.go
	protoc  --go_out=paths=source_relative:. ./internal/oplog/oplog_test/oplog_test.proto
	protoc-go-inject-tag -input=./internal/oplog/oplog_test/oplog_test.pb.go


.PHONY: proto