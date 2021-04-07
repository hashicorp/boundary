#!/bin/sh

set -e

if [ -z "$UI_CLONE_DIR" ]; then
	echo "Must set UI_CLONE_DIR"; exit 1
fi

if [ -z "$UI_ASSETS_FILE" ]; then
	echo "Must set UI_ASSETS_FILE"; exit 1
fi

(
	cd "$UI_CLONE_DIR"
	if ! yarn install && yarn build; then
		echo "Please ensure Node v14+ and Yarn v1.22.10+ are installed."
	fi
)

uidir="${UI_CLONE_DIR}/ui/admin/dist"

go-bindata -fs -o "$UI_ASSETS_FILE.tmp" -pkg ui -prefix "${uidir}" "${uidir}" "${uidir}/assets"

printf "// +build ui\n" > "$UI_ASSETS_FILE"
cat "$UI_ASSETS_FILE.tmp" >> "$UI_ASSETS_FILE"
rm "$UI_ASSETS_FILE.tmp"
