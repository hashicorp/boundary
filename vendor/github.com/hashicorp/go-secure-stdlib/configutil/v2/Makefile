PLUGIN_TMP_DIR := $(shell mktemp -d)

test-plugin:
	go build -o "${PLUGIN_TMP_DIR}/aeadplugin" testplugins/aead/main.go
	PLUGIN_PATH="${PLUGIN_TMP_DIR}/aeadplugin" go test -v -run 'TestFilePlugin|TestConfigureWrapperPropagatesOptions'

.PHONY: test-plugin
