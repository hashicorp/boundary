#!/bin/bash
pushd ../
make dev
cp bin/watchtower /tmp/ 
popd

go test -v
