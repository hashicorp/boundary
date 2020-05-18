# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/watchtower

GENERATED_CODE := $(shell  find ${THIS_DIR} -name '*.gen.go' && find ${THIS_DIR} -name '*.pb.go' && find ${THIS_DIR} -name '*.pb.gw.go')

export GEN_BASEPATH := $(shell pwd)

stuff:
	@echo ${THIS_DIR}

bootstrap:
	go generate -tags tools tools/tools.go

gen: cleangen proto api migrations

api:
	$(MAKE) --environment-overrides -C api/internal/genapi api

migrations:
	$(MAKE) --environment-overrides -C internal/db/migrations/genmigrations migrations

cleangen:
	@rm -f ${GENERATED_CODE}

### oplog requires protoc-gen-go v1.20.0 or later
# GO111MODULE=on go get -u github.com/golang/protobuf/protoc-gen-go@v1.40
proto: protolint protobuild

protolint:
	@buf check lint

protobuild:
	# To add a new directory containing a proto pass the  proto's root path in
	# through the --proto_path flag.
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
	cp -R ${TMP_DIR}/${REPO_PATH}/* ${THIS_DIR}

	@protoc --proto_path=internal/proto/local --proto_path=internal/proto/third_party --swagger_out=logtostderr=true,disable_default_errors=true,include_package_in_tags=true,fqn_for_swagger_name=true,allow_merge,merge_file_name=controller:internal/gen/. internal/proto/local/controller/api/services/v1/*.proto
	@protoc-go-inject-tag -input=./internal/oplog/store/oplog.pb.go
	@protoc-go-inject-tag -input=./internal/oplog/oplog_test/oplog_test.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/scope.pb.go
	@protoc-go-inject-tag -input=./internal/db/db_test/db_test.pb.go
	@rm -R ${TMP_DIR}


.PHONY: api bootstrap gen migrations proto

.NOTPARALLEL:
