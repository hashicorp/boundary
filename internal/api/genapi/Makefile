# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

export API_GEN_BASEPATH := ${GEN_BASEPATH}/api

api:
	go run .
	goimports -w ${API_GEN_BASEPATH}
	gofumpt -w ${API_GEN_BASEPATH}

.PHONY: api
