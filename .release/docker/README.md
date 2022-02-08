# Boundary Docker Image

The root of this repository contains the officially supported HashiCorp Dockerfile to build the hashicorp/boundary docker image. The dev docker image should be built for local dev and testing, while the production docker image is built in CI and makes use of CI-built binaries. The official docker image is built using the official binaries from releases.hashicorp.com.

## Build

See the Makefile targets in the root of this repository for building Boundary images in either
development or release modes:

  - `make docker-build-dev`
  - `make docker-multiarch-build`
  - `make docker-build`
  - `make docker`

## Usage

### Dev Mode

Due to the limitations of `boundary dev` running and maintaining a postgres docker container, it's not recommended
to run `dev` mode inside docker. To do so will require knowledge of running [docker-in-docker](https://hub.docker.com/_/docker), and the caveats
associated with it. 

### Default Configuration

The default behavior of the Boundary docker image is to run `boundary server -config /boundary/config.hcl`. The default
configuration can be found in this directory and it's highly recommended that end users replace this configuration 
with one that suites their environment. 

### Postgres

The usage instructions in this README assume you have an external postgres database (version 11 or greater) to run 
boundary server with. If you want to get started quickly, you can start a local postgres in docker:

```bash
docker run -it -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres postgres
```

The postgres URL setting is defined with `env://BOUNDARY_POSTGRES_URL` so it can be easily overidden with `-e`
during docker run:

```bash
docker run <truncated> -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' <truncated>
```
### Database Init

If you're starting with a new, unused postgres instance, initialize the database using the default config.hcl:

```bash
docker run \
  --network host \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  boundary database init -config /boundary/config.hcl
```

If you want to run this with your own config.hcl (assuming config.hcl is located at `$(pwd)/config.hcl`):

```bash
docker run \
  --network host \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  -v "$(pwd)":/boundary/ \
  boundary database init -config /boundary/config.hcl
```

### Server
Start a Boundary server using the default `config.hcl`:

```bash
docker run \
  --network host \
  -p 9200:9200 \
  -p 9201:9201 \
  -p 9202:9202 \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  boundary
```

Start a Boundary server using your own `config.hcl`, assuming it's located at `$(pwd)/config.hcl`:

```bash
docker run \
  --network host \
  -p 9200:9200 \
  -p 9201:9201 \
  -p 9202:9202 \
  -v "$(pwd)":/boundary/ \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  boundary
```