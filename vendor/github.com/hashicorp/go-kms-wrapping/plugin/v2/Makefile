PLUGIN_TMP_DIR := $(shell mktemp -d)

test-plugin-aead:
	go build -o "${PLUGIN_TMP_DIR}/aeadplugin" testplugins/aead/main.go
	PLUGIN_PATH="${PLUGIN_TMP_DIR}/aeadplugin" go test -v -run TestAeadPluginWrapper

test-plugin-interfaces:
	go build -o "${PLUGIN_TMP_DIR}/wrapperplugin" testplugins/wrapper/main.go
	go build -o "${PLUGIN_TMP_DIR}/initfinalizerhmaccomputerplugin" testplugins/initfinalizerhmaccomputer/main.go
	PLUGIN_PATH="${PLUGIN_TMP_DIR}" go test -v -run TestInterface


.PHONY: test-plugin-aead test-plugin-interfaces
