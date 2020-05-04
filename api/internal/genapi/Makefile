# Determine this makefile's path.
# Be sure to place this BEFORE `include` directives, if any.
THIS_FILE := $(lastword $(MAKEFILE_LIST))

api:
	go run -tags genapi .
	goimports -w ${APIGEN_BASEPATH}/api

.PHONY: api
