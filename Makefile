# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

PROTO_GEN_OUT = proto/gen
TMP_BUF_IMG := $(shell mktemp -t buf_img)

### oplog requires protoc-gen-go v1.20.0 or later 	
# GO111MODULE=on go get -u google.golang.org/protobuf/cmd/protoc-gen-go@v1.20.1
proto: protobuild cleanup

protobuild:
	@mkdir -p ${PROTO_GEN_OUT}
	@buf image build -o - > ${TMP_BUF_IMG}
	@protoc --descriptor_set_in=${TMP_BUF_IMG} --go_out=plugins=grpc,paths=source_relative:${PROTO_GEN_OUT} --grpc-gateway_out=logtostderr=true,paths=source_relative:${PROTO_GEN_OUT} --go-json_out=logtostderr=true:${PROTO_GEN_OUT} --swagger_out=logtostderr=true,allow_merge,merge_file_name=controller:${PROTO_GEN_OUT} hostcatalogs.proto
	protoc  --go_out=paths=source_relative:. ./internal/oplog/any_operation.proto
	protoc  --go_out=paths=source_relative:. ./internal/oplog/store/oplog.proto
	protoc-go-inject-tag -input=./internal/oplog/store/oplog.pb.go
	protoc  --go_out=paths=source_relative:. ./internal/oplog/oplog_test/oplog_test.proto
	protoc-go-inject-tag -input=./internal/oplog/oplog_test/oplog_test.pb.go


cleanup:
	@rm ${TMP_BUF_IMG}

.PHONY: proto

.NOTPARALLEL: