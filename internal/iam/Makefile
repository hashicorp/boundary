# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))


### oplog requires protoc-gen-go v1.20.0 or later 	
# GO111MODULE=on go get -u google.golang.org/protobuf/cmd/protoc-gen-go@v1.20.1
proto:
	protoc  --proto_path=./store --go_out=paths=source_relative:./store ./store/scope.proto
	protoc-go-inject-tag -input=./store/scope.pb.go

	protoc  --proto_path=./store --go_out=paths=source_relative:./store ./store/timestamp.proto

	protoc  --proto_path=./store --go_out=paths=source_relative:./store ./store/user.proto
	protoc-go-inject-tag -input=./store/user.pb.go

.PHONY: proto