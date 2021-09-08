# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

export CLI_GEN_BASEPATH := ${GEN_BASEPATH}/internal/cmd/commands

cli:
	go run .
	goimports -w ${CLI_GEN_BASEPATH}
	gofumpt -w ${CLI_GEN_BASEPATH}

.PHONY: cli
