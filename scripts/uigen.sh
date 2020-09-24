#!/bin/sh

set -e

ui_commitish="${UI_COMMITISH:-develop}"

targetdir="internal/ui"
shafile="${targetdir}/VERSION"
shafileabs="$(pwd)/${shafile}"
tempdir="${targetdir}/source"
uirepodir="${tempdir}/boundary-ui"
mkdir -p "${tempdir}"
echo "*" > "${tempdir}/.gitignore"

if ! [ -d "${uirepodir}/.git" ]; then
	git clone https://github.com/hashicorp/boundary-ui "${uirepodir}"
fi

(
	cd "${uirepodir}"
	git reset --hard
	git fetch origin "${ui_commitish}"
	git checkout "${ui_commitish}"
	if ! docker-compose -f docker-compose-embedding.yml run build; then
		echo "==> UI build failed."
		exit 1
	fi
	git log -n1 --pretty=oneline > "${shafileabs}"
	echo "# Above commit is used for production builds." >> "${shafileabs}"
)

uidir="${uirepodir}/ui/core/dist"

target="${targetdir}/assets.go"

go-bindata -fs -o "${target}.tmp" -pkg ui -prefix "${uidir}" "${uidir}" "${uidir}/assets"

printf "// +build ui\n" > "${target}"
cat "${target}.tmp" >> "${target}"
rm "${target}.tmp"

rm -rf "$tempdir"
