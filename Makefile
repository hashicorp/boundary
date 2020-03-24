# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

proto:
	protoc  --go_out=paths=source_relative:. ./internal/oplog/any.proto
	protoc  --go_out=paths=source_relative:. ./internal/oplog/store/oplog.proto
	protoc-go-inject-tag -input=./internal/oplog/store/oplog.pb.go
	protoc  --go_out=paths=source_relative:. ./internal/oplog/oplog_test/oplog_test.proto
	protoc-go-inject-tag -input=./internal/oplog/oplog_test/oplog_test.pb.go


.PHONY: proto