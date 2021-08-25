# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

migrations:
	go run .
	goimports -w ${GEN_BASEPATH}/internal/db/schema
	gofumpt -w ${GEN_BASEPATH}/internal/db/schema

check: migrations
	@git status --porcelain ${GEN_BASEPATH}/internal/db/schema
	@git diff --exit-code ${GEN_BASEPATH}/internal/db/schema

.PHONY: migrations check
