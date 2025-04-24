# Boundary Docker Image

The root of this repository contains the officially supported HashiCorp Dockerfile to build the hashicorp/boundary docker image.
The dev docker image should be built for local dev and testing,
while the production docker image is built in CI and makes use of CI-built binaries.
The official docker image is built using the official binaries from releases.hashicorp.com.

## Build

See the Makefile targets in the root of this repository
for building Boundary images in either development or release modes:

  - `make docker-build-dev`
  - `make docker-multiarch-build`
  - `make docker-build`
  - `make docker`
