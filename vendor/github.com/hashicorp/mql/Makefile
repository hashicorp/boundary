# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/mql

.PHONY: fmt
fmt:
	gofumpt -w $$(find . -name '*.go')

.PHONY: gen
gen: fmt copywrite

.PHONY: test
test: 
	go test -race -count=1 ./...

.PHONY: test-all
test-all: test test-postgres

.PHONY: test-postgres
test-postgres:
	##############################################################
	# this test is dependent on first running: docker-compose up
	##############################################################
	cd ./tests/postgres && \
	DB_DIALECT=postgres DB_DSN="postgresql://go_db:go_db@localhost:9920/go_db?sslmode=disable"  go test -race -count=1 ./...

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

.PHONY: tools
tools:
	go generate -tags tools tools/tools.go
	go install github.com/hashicorp/copywrite@v0.15.0

.PHONY: copywrite
copywrite:
	copywrite headers