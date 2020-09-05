#!/bin/sh

set -e

origdir=$(pwd)
tempdir=$(mktemp -d update-ui-assets.XXXXXX)
ui_commitish=${UI_COMMITISH:-develop}

cd $tempdir
git clone https://github.com/hashicorp/boundary-ui
cd boundary-ui
git fetch origin ${ui_commitish}
git checkout ${ui_commitish}

docker-compose -f docker-compose-embedding.yml run build

cd $origdir

go-bindata -fs -o internal/ui/assets.go -pkg ui -prefix "${origdir}/${tempdir}/boundary-ui/ui/core/dist" "${origdir}/${tempdir}/boundary-ui/ui/core/dist" "${origdir}/${tempdir}/boundary-ui/ui/core/dist/assets"


rm -rf $tempdir
