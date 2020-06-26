#!/bin/sh

set -e

origdir=$(pwd)
tempdir=$(mktemp -d update-ui-assets.XXXXXX)

cd $tempdir
git clone https://github.com/hashicorp/watchtower-ui
cd watchtower-ui

docker-compose -f docker-compose-embedding.yml run build_production

cd $origdir

go-bindata -fs -o internal/ui/assets.go -pkg ui -prefix "${origdir}/${tempdir}/watchtower-ui/ui/core/dist" "${origdir}/${tempdir}/watchtower-ui/ui/core/dist"

rm -rf $tempdir
