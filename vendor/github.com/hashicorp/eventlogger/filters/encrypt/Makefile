
THIS_FILE := $(lastword $(MAKEFILE_LIST))
THIS_DIR := $(dir $(realpath $(firstword $(MAKEFILE_LIST))))

TMP_DIR := $(shell mktemp -d)
REPO_PATH := github.com/hashicorp/eventlogger/filters/encrypt


# currently, protobufs are only used for testing the filtering of event payloads
# which include protobufs.
proto:  protobuild

protobuild:
	# To add a new directory containing a proto pass the  proto's root path in
	# through the --proto_path flag.
	@bash scripts/protoc_gen_plugin.bash \
		"--proto_path=testing/proto" \
		"--plugin_name=go" \
		"--plugin_out=${TMP_DIR}"
	# Move the generated files from the tmp file subdirectories into the current
	# repo.
	cp -R ${TMP_DIR}/${REPO_PATH}/* ${THIS_DIR}

	# inject classification/filter tags
	@protoc-go-inject-tag -input=./testing/resources/protopayload/proto_payload.pb.go


