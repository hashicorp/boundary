# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/boundary

GENERATED_CODE := $(shell  find ${THIS_DIR} -name '*.gen.go' && find ${THIS_DIR} -name '*.pb.go' && find ${THIS_DIR} -name '*.pb.gw.go')

CGO_ENABLED?=0

export GEN_BASEPATH := $(shell pwd)

.PHONY: api
api:
	$(MAKE) --environment-overrides -C internal/api/genapi api

.PHONY: cli
cli:
	$(MAKE) --environment-overrides -C internal/cmd/gencli cli

.PHONY: tools
tools:
	go generate -tags tools tools/tools.go

.PHONY: cleangen
cleangen:
	@rm -f ${GENERATED_CODE}

.PHONY: install-no-plugins
install-no-plugins: export SKIP_PLUGIN_BUILD=1
install-no-plugins: install

.PHONY: dev
dev:
	@echo "This command has changed. Please use:"
	@echo "==> make build"
	@echo "      to build the binary into the bin/ directory"
	@echo "==> make install"
	@echo "      to build the binary and install it into GOPATH/bin"

.PHONY: build
build: BUILD_TAGS+=ui
build: build-ui-ifne
	@echo "==> Building Boundary with UI features enabled"
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

.PHONY: install
install: export BOUNDARY_INSTALL_BINARY=1
install: build

.PHONY: fmt
fmt:
	gofumpt -w $$(find . -name '*.go' | grep -v pb.go | grep -v pb.gw.go)

# Set env for all UI targets.
UI_TARGETS := update-ui-version build-ui build-ui-ifne
# Note the extra .tmp path segment in UI_CLONE_DIR is significant and required.
$(UI_TARGETS): export UI_CLONE_DIR      := internal/ui/.tmp/boundary-ui
$(UI_TARGETS): export UI_VERSION_FILE   := internal/ui/VERSION
$(UI_TARGETS): export UI_ASSETS_FILE    := internal/ui/assets.go
$(UI_TARGETS): export UI_DEFAULT_BRANCH := main
$(UI_TARGETS): export UI_CURRENT_COMMIT := $(shell head -n1 < "$(UI_VERSION_FILE)" | cut -d' ' -f1)
$(UI_TARGETS): export UI_COMMITISH ?=

.PHONY: update-ui-version
update-ui-version:
	@if [ -z "$(UI_COMMITISH)" ]; then \
		echo "==> Setting UI version to latest commit on branch '$(UI_DEFAULT_BRANCH)'"; \
		export UI_COMMITISH="$(UI_DEFAULT_BRANCH)"; \
	else \
		echo "==> Setting to latest commit matching '$(UI_COMMITISH)'"; \
	fi; \
	./scripts/uiclone.sh && ./scripts/uiupdate.sh

.PHONY: build-ui
build-ui:
	@if [ -z "$(UI_COMMITISH)" ]; then \
		echo "==> Building default UI version from $(UI_VERSION_FILE): $(UI_CURRENT_COMMIT)"; \
		export UI_COMMITISH="$(UI_CURRENT_COMMIT)"; \
	else \
		echo "==> Building custom UI version $(UI_COMMITISH)"; \
	fi; \
	./scripts/uiclone.sh && ./scripts/uigen.sh

.PHONY: build-ui-ifne
build-ui-ifne:
ifeq (,$(wildcard internal/ui/.tmp/boundary-ui))
	@echo "==> No UI assets found, building..."
	@$(MAKE) build-ui
else
	@echo "==> UI assets found, use build-ui target to update"
endif

.PHONY: perms-table
perms-table:
	@go run internal/website/permstable/permstable.go

.PHONY: gen
gen: cleangen proto api cli perms-table fmt

### oplog requires protoc-gen-go v1.20.0 or later
# GO111MODULE=on go get -u github.com/golang/protobuf/protoc-gen-go@v1.40
.PHONY: proto
proto: protolint protobuild

.PHONY: protobuild
protobuild:
	# To add a new directory containing a proto pass the  proto's root path in
	# through the --proto_path flag.
	@bash scripts/protoc_gen_plugin.bash \
		"--proto_path=internal/proto/local" \
		"--proto_include_path=internal/proto/third_party" \
		"--plugin_name=go" \
		"--plugin_out=${TMP_DIR}"
	@bash scripts/protoc_gen_plugin.bash \
		"--proto_path=internal/proto/local" \
		"--proto_include_path=internal/proto/third_party" \
		"--plugin_name=go-grpc" \
		"--plugin_out=${TMP_DIR}"
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
	@protoc-go-inject-tag -input=./internal/host/plugin/store/host.pb.go
	@protoc-go-inject-tag -input=./internal/plugin/host/store/plugin.pb.go
	@protoc-go-inject-tag -input=./internal/plugin/store/plugin.pb.go
	@protoc-go-inject-tag -input=./internal/authtoken/store/authtoken.pb.go
	@protoc-go-inject-tag -input=./internal/auth/store/account.pb.go
	@protoc-go-inject-tag -input=./internal/auth/password/store/password.pb.go
	@protoc-go-inject-tag -input=./internal/auth/password/store/argon2.pb.go
	@protoc-go-inject-tag -input=./internal/kms/store/root_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/database_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/oplog_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/token_key.pb.go	
	@protoc-go-inject-tag -input=./internal/kms/store/session_key.pb.go
	@protoc-go-inject-tag -input=./internal/kms/store/oidc_key.pb.go		
	@protoc-go-inject-tag -input=./internal/target/store/target.pb.go
	@protoc-go-inject-tag -input=./internal/target/targettest/store/target.pb.go
	@protoc-go-inject-tag -input=./internal/target/tcp/store/target.pb.go
	@protoc-go-inject-tag -input=./internal/auth/oidc/store/oidc.pb.go
	@protoc-go-inject-tag -input=./internal/scheduler/job/store/job.pb.go
	@protoc-go-inject-tag -input=./internal/credential/store/credential.pb.go
	@protoc-go-inject-tag -input=./internal/credential/vault/store/vault.pb.go
	@protoc-go-inject-tag -input=./internal/servers/servers.pb.go
	@protoc-go-inject-tag -input=./internal/kms/store/audit_key.pb.go

	# inject classification tags (see: https://github.com/hashicorp/go-eventlogger/tree/main/filters/encrypt)
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/auth_method_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/authmethods/auth_method.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/scopes/scope.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/servers/services/session_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/targets/target.pb.go

	# these protos, services and openapi artifacts are purely for testing purposes
	@protoc-go-inject-tag -input=./internal/gen/testing/event/event.pb.go
	@protoc --proto_path=internal/proto/local --proto_path=internal/proto/third_party --openapiv2_out=json_names_for_fields=false,logtostderr=true,disable_default_errors=true,include_package_in_tags=true,fqn_for_openapi_name=true,allow_merge,merge_file_name=testing:internal/gen/testing/event/. internal/proto/local/testing/event/v1/*.proto


	@rm -R ${TMP_DIR}

.PHONY: protolint
protolint:
	@buf lint
	#@buf breaking --against 'https://github.com/hashicorp/boundary.git#branch=stable-website'

.PHONY: website
# must have nodejs and npm installed
website: website-install website-start

.PHONY: website-install
website-install:
	@npm install --prefix website/

.PHONY: website-start
website-start:
	@npm start --prefix website/

.PHONY: test-database-up
test-database-up:
	make -C testing/dbtest/docker database-up

.PHONY: test-database-down
test-database-down:
	make -C testing/dbtest/docker clean

.PHONY: test-ci
test-ci: export CI_BUILD=1
test-ci:
	CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"
	~/.go/bin/go test ./... -v $(TESTARGS) -timeout 120m

.PHONY: test-sql
test-sql:
	$(MAKE) -C internal/db/sqltest/ test

.PHONY: test
test:
	go test ./... -timeout 30m

.PHONY: test-sdk
test-sdk:
	$(MAKE) -C sdk/ test

.PHONY: test-api
test-api:
	$(MAKE) -C api/ test

.PHONY: test-all
test-all: test-sdk test-api test

.PHONY: install-go
install-go:
	./ci/goinstall.sh

# Docker build and publish variables and targets
REGISTRY_NAME?=docker.io/hashicorp
IMAGE_NAME=boundary
VERSION?=0.7.4
IMAGE_TAG=$(REGISTRY_NAME)/$(IMAGE_NAME):$(VERSION)
IMAGE_TAG_DEV=$(REGISTRY_NAME)/$(IMAGE_NAME):latest-$(shell git rev-parse --short HEAD)

.PHONY: docker
docker: docker-build

.PHONY: docker-build
# Builds from the releases.hashicorp.com official binary
docker-build:
	docker build \
		--tag $(IMAGE_TAG) \
		--tag hashicorp/boundary:latest \
		--target=official \
		--build-arg VERSION=$(VERSION) \
		.

.PHONY: docker-multiarch-build
# Builds multiarch from the releases.hashicorp.com official binary
docker-multiarch-build:
	docker buildx build \
		--tag $(IMAGE_TAG) \
		--tag hashicorp/boundary:latest \
		--target=official \
		--build-arg VERSION=$(VERSION) \
		--platform linux/amd64,linux/arm64 \
		.

.PHONY: docker-build-dev
# Builds from the locally generated binary in ./bin/
docker-build-dev: export GOOS=linux
docker-build-dev: export GOARCH=amd64
docker-build-dev: build
	docker build \
		--tag $(IMAGE_TAG_DEV) \
		--target=dev \
		--build-arg=boundary \
		.

.NOTPARALLEL:

.PHONY: ci-config
ci-config:
	@$(MAKE) -C .circleci ci-config

.PHONY: ci-verify
ci-verify:
	@$(MAKE) -C .circleci ci-verify

.PHONY: version
# This is used for release builds by .github/workflows/build.yml
version:
	@go run ./cmd/boundary version | awk '/Version Number:/ { print $$3 }'
