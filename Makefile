# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/watchtower

GENERATED_CODE := $(shell  find ${THIS_DIR} -name '*.gen.go' && find ${THIS_DIR} -name '*.pb.go' && find ${THIS_DIR} -name '*.pb.gw.go')

CGO_ENABLED?=0

export GEN_BASEPATH := $(shell pwd)

api:
	$(MAKE) --environment-overrides -C api/internal/genapi api

bootstrap:
	go generate -tags tools tools/tools.go

cleangen:
	@rm -f ${GENERATED_CODE}

dev: BUILD_TAGS+=dev
dev:
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' WATCHTOWER_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

gen: cleangen proto api migrations

migrations:
	$(MAKE) --environment-overrides -C internal/db/migrations/genmigrations migrations

### oplog requires protoc-gen-go v1.20.0 or later
# GO111MODULE=on go get -u github.com/golang/protobuf/protoc-gen-go@v1.40
proto: protolint protobuild

protobuild:
	# To add a new directory containing a proto pass the  proto's root path in
	# through the --proto_path flag.
	@bash scripts/protoc_gen_plugin.bash \
		"--proto_path=internal/proto/local" \
		"--proto_include_path=internal/proto/third_party" \
		"--plugin_name=go" \
		"--plugin_out=plugins=grpc:${TMP_DIR}"
	@bash scripts/protoc_gen_plugin.bash \
		"--proto_path=internal/proto/local/" \
		"--proto_include_path=internal/proto/third_party" \
		"--plugin_name=grpc-gateway" \
		"--plugin_out=logtostderr=true:${TMP_DIR}"

	# Move the generated files from the tmp file subdirectories into the current repo.
	cp -R ${TMP_DIR}/${REPO_PATH}/* ${THIS_DIR}

	@protoc --proto_path=internal/proto/local --proto_path=internal/proto/third_party --swagger_out=logtostderr=true,disable_default_errors=true,include_package_in_tags=true,fqn_for_swagger_name=true,allow_merge,merge_file_name=controller:internal/gen/. internal/proto/local/controller/api/services/v1/*.proto
	@protoc-go-inject-tag -input=./internal/oplog/store/oplog.pb.go
	@protoc-go-inject-tag -input=./internal/oplog/oplog_test/oplog_test.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/user.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/scope.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/group.pb.go
	@protoc-go-inject-tag -input=./internal/db/db_test/db_test.pb.go
	@protoc-go-inject-tag -input=./internal/host/static/store/static.pb.go
	@protoc-go-inject-tag -input=./internal/usersessions/store/session.pb.go
	@rm -R ${TMP_DIR}

protolint:
	@buf check lint

.PHONY: api bootstrap gen migrations proto

.NOTPARALLEL:
