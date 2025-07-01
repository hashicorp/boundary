# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/dbw

.PHONY: tools
tools:
	go generate -tags tools tools/tools.go
	go install github.com/bufbuild/buf/cmd/buf@v1.15.1
	go install github.com/hashicorp/copywrite@v0.15.0

.PHONY: fmt
fmt:
	gofumpt -w $$(find . -name '*.go' ! -name '*pb.go')
	buf format -w

.PHONY: copywrite
copywrite:
	copywrite headers

.PHONY: gen
gen: proto fmt copywrite

.PHONY: test
test: 
	go test -race -count=1 ./...

.PHONY: test-all
test-all: test-sqlite test-postgres

.PHONY: test-sqlite
test-sqlite:
	DB_DIALECT=sqlite go test -race -count=1 ./...

.PHONY: test-postgres
test-postgres:
	##############################################################
	# this test is dependent on first running: docker-compose up
	##############################################################
	DB_DIALECT=postgres DB_DSN="postgresql://go_db:go_db@localhost:9920/go_db?sslmode=disable"  go test -race -count=1 ./...

### db tags requires protoc-gen-go v1.20.0 or later
# GO111MODULE=on go get -u github.com/golang/protobuf/protoc-gen-go@v1.40
.PHONY: proto
proto: protolint protobuild

.PHONY: protobuild
protobuild:
	buf generate
	@protoc-go-inject-tag -input=./internal/dbtest/dbtest.pb.go

.PHONY: protolint
protolint:
	@buf lint
	# if/when this becomes a public repo, we can add this check
	# @buf check breaking --against
	# 'https://github.com/hashicorp/go-dbw.git#branch=main'

# coverage-diff will run a new coverage report and check coverage.log to see if
# the coverage has changed.  
.PHONY: coverage-diff
coverage-diff: 
	cd coverage && \
	./coverage.sh && \
	./cov-diff.sh coverage.log && \
	if ./cov-diff.sh ./coverage.log; then git restore coverage.log; fi

# coverage will generate a report, badge and log.  when you make changes, run
# this and check in the changes to publish a new/latest coverage report and
# badge. 
.PHONY: coverage
coverage: 
	cd coverage && \
	./coverage.sh && \
	if ./cov-diff.sh ./coverage.log; then git restore coverage.log; fi
