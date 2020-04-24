# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/watchtower

### oplog requires protoc-gen-go v1.20.0 or later
# GO111MODULE=on go get -u github.com/golang/protobuf/protoc-gen-go@v1.40
proto: protolint protobuild cleanup

protolint:
	@buf check lint

protobuild:
    # To add a new directory containing a proto pass the  proto's root path in through the --proto_path flag.
	@bash make/protoc_gen_plugin.bash \
		"--proto_path=internal/proto/local" \
		"--proto_include_path=internal/proto/third_party" \
		"--plugin_name=go" \
		"--plugin_out=plugins=grpc:${TMP_DIR}"
	@bash make/protoc_gen_plugin.bash \
		"--proto_path=internal/proto/local/" \
		"--proto_include_path=internal/proto/third_party" \
		"--plugin_name=grpc-gateway" \
		"--plugin_out=logtostderr=true:${TMP_DIR}"

	# Move the generated files from the tmp file subdirectories into the current repo.
	cp -R ${TMP_DIR}/${REPO_PATH}/* .

	@protoc --proto_path=internal/proto/local --proto_path=internal/proto/third_party --swagger_out=logtostderr=true,allow_merge,merge_file_name=controller:internal/gen/. internal/proto/local/controller/api/v1/*.proto
	@protoc-go-inject-tag -input=./internal/oplog/store/oplog.pb.go
	@protoc-go-inject-tag -input=./internal/oplog/oplog_test/test_structures.pb.go


cleanup:
	@rm -R ${TMP_DIR}


.PHONY: proto

.NOTPARALLEL:
