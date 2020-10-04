# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/boundary

GENERATED_CODE := $(shell  find ${THIS_DIR} -name '*.gen.go' && find ${THIS_DIR} -name '*.pb.go' && find ${THIS_DIR} -name '*.pb.gw.go')

CGO_ENABLED?=0

export GEN_BASEPATH := $(shell pwd)

api:
	$(MAKE) --environment-overrides -C api/internal/genapi api

tools:
	go generate -tags tools tools/tools.go

cleangen:
	@rm -f ${GENERATED_CODE}

dev: BUILD_TAGS+=dev
dev: BUILD_TAGS+=ui
dev: build-ui-ifne
	@echo "==> Building Boundary with dev and UI features enabled"
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' BOUNDARY_DEV_BUILD=1 sh -c "'$(CURDIR)/scripts/build.sh'"

bin: BUILD_TAGS+=ui
bin: build-ui
	@echo "==> Building Boundary with UI features enabled"
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

fmt:
	goimports -w $$(find . -name '*.go' | grep -v pb.go | grep -v pb.gw.go)

build-ui:
	@scripts/uigen.sh

build-ui-ifne:
ifeq (,$(wildcard internal/ui/assets.go))
	@echo "==> No UI assets found, building..."
	@scripts/uigen.sh
else
	@echo "==> UI assets found, use build-ui target to update"
endif

perms-table:
	@go run internal/website/permstable/permstable.go

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

	@protoc --proto_path=internal/proto/local --proto_path=internal/proto/third_party --openapiv2_out=json_names_for_fields=false,logtostderr=true,disable_default_errors=true,include_package_in_tags=true,fqn_for_openapi_name=true,allow_merge,merge_file_name=controller:internal/gen/. internal/proto/local/controller/api/services/v1/*.proto
	@protoc-go-inject-tag -input=./internal/oplog/store/oplog.pb.go
	@protoc-go-inject-tag -input=./internal/oplog/oplog_test/oplog_test.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/group_member.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/role.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/principal_role.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/role_grant.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/user.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/scope.pb.go
	@protoc-go-inject-tag -input=./internal/iam/store/group.pb.go
	@protoc-go-inject-tag -input=./internal/db/db_test/db_test.pb.go
	@protoc-go-inject-tag -input=./internal/host/store/host.pb.go
	@protoc-go-inject-tag -input=./internal/host/static/store/static.pb.go
	@protoc-go-inject-tag -input=./internal/authtoken/store/authtoken.pb.go
	@protoc-go-inject-tag -input=./internal/auth/store/account.pb.go
	@protoc-go-inject-tag -input=./internal/auth/password/store/password.pb.go
	@protoc-go-inject-tag -input=./internal/auth/password/store/argon2.pb.go
	@protoc-go-inject-tag -input=./internal/kms/store/root_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/database_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/oplog_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/token_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/session_key.pb.go	
	@protoc-go-inject-tag -input=./internal/target/store/target.pb.go

	@rm -R ${TMP_DIR}

protolint:
	@buf check lint

# must have nodejs and npm installed
website: website-install website-start

website-install:
	@npm install --prefix website/

website-start:
	@npm start --prefix website/

test-ci: install-go
	~/.go/bin/go test ./... -v $(TESTARGS) -timeout 120m

install-go:
	./ci/goinstall.sh

.PHONY: api tools gen migrations proto website ci-config ci-verify

.NOTPARALLEL:

ci-config:
	@$(MAKE) -C .circleci ci-config

ci-verify:
	@$(MAKE) -C .circleci ci-verify

PACKAGESPEC_CIRCLECI_CONFIG := .circleci/config/@build-release.yml
PACKAGESPEC_HOOK_POST_CI_CONFIG := $(MAKE) ci-config

-include packagespec.mk
