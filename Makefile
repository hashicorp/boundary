# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/boundary

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
	go install github.com/bufbuild/buf/cmd/buf@v1.3.1
	go install github.com/mfridman/tparse@v0.10.3

.PHONY: cleangen
cleangen:
	@rm -f $(shell  find ${THIS_DIR} -name '*.gen.go' && find ${THIS_DIR} -name '*.pb.go' && find ${THIS_DIR} -name '*.pb.gw.go')

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

.PHONY: build-memprof
build-memprof: BUILD_TAGS+=memprofiler
build-memprof:
	@echo "==> Building Boundary with memory profiling enabled"
	@CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"

# Format Go files, ignoring files marked as generated through the header defined at
# https://pkg.go.dev/cmd/go#hdr-Generate_Go_files_by_processing_source
.PHONY: fmt
fmt:
	grep -L -R "^\/\/ Code generated .* DO NOT EDIT\.$$" --exclude-dir=.git --include="*.go" . | xargs gofumpt -w
	buf format -w

# Set env for all UI targets.
UI_TARGETS := update-ui-version build-ui build-ui-ifne clean-ui
# Note the extra .tmp path segment in UI_CLONE_DIR is significant and required.
$(UI_TARGETS): export UI_CLONE_DIR      := internal/ui/.tmp/boundary-ui
$(UI_TARGETS): export UI_VERSION_FILE   := internal/ui/VERSION
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
	./scripts/uiupdate.sh

.PHONY: build-ui
build-ui:
	@if [ -z "$(UI_COMMITISH)" ]; then \
		echo "==> Building default UI version from $(UI_VERSION_FILE): $(UI_CURRENT_COMMIT)"; \
		export UI_COMMITISH="$(UI_CURRENT_COMMIT)"; \
	else \
		echo "==> Building custom UI version $(UI_COMMITISH)"; \
	fi; \
	./scripts/build-ui.sh

.PHONY: clean-ui
clean-ui:
	rm -rf ${UI_CLONE_DIR}

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
	@buf generate -o "${TMP_DIR}"

	# Move the generated files from the tmp file subdirectories into the current repo.
	cp -R ${TMP_DIR}/${REPO_PATH}/* ${THIS_DIR}

	@buf generate --template buf.openapiv2.gen.yaml --path internal/proto/controller/api/services/v1/

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
	@protoc-go-inject-tag -input=./internal/kms/store/data_key_version_destruction_job.pb.go
	@protoc-go-inject-tag -input=./internal/kms/store/data_key_version_destruction_job_run.pb.go
	@protoc-go-inject-tag -input=./internal/kms/store/data_key_version_destruction_job_run_allowed_table_name.pb.go
	@protoc-go-inject-tag -input=./internal/server/store/controller.pb.go
	@protoc-go-inject-tag -input=./internal/server/store/worker.pb.go
	@protoc-go-inject-tag -input=./internal/server/store/root_certificate.pb.go
	@protoc-go-inject-tag -input=./internal/server/store/worker_auth.pb.go
	@protoc-go-inject-tag -input=./internal/target/store/target.pb.go
	@protoc-go-inject-tag -input=./internal/target/targettest/store/target.pb.go
	@protoc-go-inject-tag -input=./internal/target/tcp/store/target.pb.go
	@protoc-go-inject-tag -input=./internal/auth/oidc/store/oidc.pb.go
	@protoc-go-inject-tag -input=./internal/scheduler/job/store/job.pb.go
	@protoc-go-inject-tag -input=./internal/credential/store/credential.pb.go
	@protoc-go-inject-tag -input=./internal/credential/vault/store/vault.pb.go
	@protoc-go-inject-tag -input=./internal/credential/static/store/static.pb.go
	@protoc-go-inject-tag -input=./internal/kms/store/audit_key.pb.go

	# inject classification tags (see: https://github.com/hashicorp/go-eventlogger/tree/main/filters/encrypt)
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/auth_method_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/authmethods/auth_method.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/scopes/scope.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/servers/services/session_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/targets/target.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/target_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/accounts/account.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/account_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/hosts/host.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/host_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/plugins/plugin.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/hostcatalogs/host_catalog.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/host_catalog_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/hostsets/host_set.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/host_set_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/authtokens/authtoken.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/authtokens_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/managedgroups/managed_group.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/managed_group_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/groups/group.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/group_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/credentialstores/credential_store.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/credential_store_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/credentiallibraries/credential_library.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/credential_library_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/credentials/credential.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/credential_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/roles/role.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/role_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/sessions/session.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/session_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/users/user.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/user_service.pb.go
	@protoc-go-inject-tag -input=./sdk/pbs/controller/api/resources/workers/worker.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/api/services/worker_service.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/servers/services/server_coordination_service.pb.go
	@protoc-go-inject-tag -input=./internal/gen/controller/servers/servers.pb.go


	# these protos, services and openapi artifacts are purely for testing purposes
	@protoc-go-inject-tag -input=./internal/gen/testing/event/event.pb.go
	@buf generate --template buf.testing.gen.yaml --path internal/proto/testing/event/v1/

	@rm -R ${TMP_DIR}

.PHONY: protolint
protolint:
	@buf lint
	# First check all protos except controller/servers and controller/storage for WIRE_JSON compatibility
	cd internal/proto && buf breaking --against 'https://github.com/hashicorp/boundary.git#branch=stable-website,subdir=internal/proto' \
		--exclude-path=controller/servers \
		--exclude-path=controller/storage \
		--config buf.breaking.json.yaml
	# Next check all protos for WIRE compatibility. WIRE is a subset of WIRE_JSON so we don't need to exclude any files.
	cd internal/proto && buf breaking --against 'https://github.com/hashicorp/boundary.git#branch=stable-website,subdir=internal/proto' \
		--config buf.breaking.wire.yaml

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

.PHONY: generate-database-dumps
generate-database-dumps:
	@$(MAKE) -C testing/dbtest/docker generate-database-dumps

.PHONY: test-ci
test-ci: export CI_BUILD=1
test-ci:
	CGO_ENABLED=$(CGO_ENABLED) BUILD_TAGS='$(BUILD_TAGS)' sh -c "'$(CURDIR)/scripts/build.sh'"
	~/.go/bin/go test ./... -v $(TESTARGS) -json -cover -timeout 120m | tparse -follow

.PHONY: test-sql
test-sql:
	$(MAKE) -C internal/db/sqltest/ test

.PHONY: test
test:
	go test ./... -timeout 30m -json -cover | tparse -follow

.PHONY: test-sdk
test-sdk:
	$(MAKE) -C sdk/ test

.PHONY: test-api
test-api:
	$(MAKE) -C api/ test

.PHONY: test-cli
test-cli:
	$(MAKE) -C internal/tests/cli test

.PHONY: test-all
test-all: test-sdk test-api test

BENCH_TIME?=1s
BENCH_COUNT?=1s
.PHONY: benchmark
benchmark:
	@go test \
		-timeout 60m \
		./internal/servers/controller/handlers/sessions/ \
		-v \
		-bench '^BenchmarkSessionList$$' \
		-benchtime $(BENCH_TIME) \
		-count $(BENCH_COUNT) \
		-run '^$$'

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

DEV_DOCKER_GOOS ?= linux
DEV_DOCKER_GOARCH ?= amd64

.PHONY: docker-build-dev
# Builds from the locally generated binary in ./bin/
docker-build-dev: export GOOS=$(DEV_DOCKER_GOOS)
docker-build-dev: export GOARCH=$(DEV_DOCKER_GOARCH)
docker-build-dev: build
	docker buildx build \
		--load \
		--platform $(DEV_DOCKER_GOOS)/$(DEV_DOCKER_GOARCH) \
		--tag $(IMAGE_TAG_DEV) \
		--target=dev \
		--build-arg=boundary \
		.
	@echo "Successfully built $(IMAGE_TAG_DEV)"

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

EDITION?=
.PHONY: edition
# This is used for release builds by .github/workflows/build.yml
edition:
	@if [ -z "$(EDITION)" ]; then \
		go run ./cmd/boundary version -format=json | jq -r '.version_metadata // "oss"'; \
	else \
		echo $(EDITION); \
	fi; \
