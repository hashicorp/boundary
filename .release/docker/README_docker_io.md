<!---
This is used for the Overview tab for the boundary docker image on hub.docker.com
https://hub.docker.com/r/hashicorp/boundary
--->

# Boundary

## Usage

See the latest updates to the Dockerfile for this image in our
[GitHub repository](https://github.com/hashicorp/boundary).

### Dev Mode

Due to the limitations of `boundary dev` running and maintaining a postgres docker container,
it's not recommended to run `dev` mode inside docker.
To do so will require knowledge of running [docker-in-docker](https://hub.docker.com/_/docker),
and the caveats associated with it.

### Default Configuration

The default behavior of the Boundary docker image is to run `boundary server -config /boundary/config.hcl`.
The included `config.hcl` file is meant to serve as an example,
and is not suitable for actual deployment.
Please see the comments within the file for more information;
full configuration details can be found on Boundary's documentation site.

### Postgres

The usage instructions in this README assume you have an external postgres database (version 12 or greater) to run boundary server with.
If you want to get started quickly, you can start a local postgres in docker:

```bash
docker run -it -p 5432:5432 -e POSTGRES_PASSWORD=postgres -e POSTGRES_USER=postgres postgres
```

The postgres URL setting is defined with `env://BOUNDARY_POSTGRES_URL` so it can be easily set with `-e` during docker run:

```bash
docker run \
    --network host \
    -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
    hashicorp/boundary
```

### Database Init

If you're starting with a new,
unused postgres instance,
initialize the database using the default `config.hcl`:

```bash
docker run \
  --network host \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  hashicorp/boundary database init -config /boundary/config.hcl
```

If you want to run this with your own `config.hcl` (assuming `config.hcl` is located at `$(pwd)/config.hcl`):

```bash
docker run \
  --network host \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  -v "$(pwd)":/boundary/ \
  hashicorp/boundary database init -config /boundary/config.hcl
```

### Database Migration

If you are updating to a newer version of boundary with a database instance
that was initialized with an older version,
you will need to apply the database migrations:

```bash
docker run \
  --network host \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  hashicorp/boundary database migrate -config /boundary/config.hcl
```

If you want to run this with your own `config.hcl` (assuming `config.hcl` is located at `$(pwd)/config.hcl`):

```bash
docker run \
  --network host \
  -e 'BOUNDARY_POSTGRES_URL=postgresql://postgres:postgres@0.0.0.0:5432/postgres?sslmode=disable' \
  -v "$(pwd)":/boundary/ \
  hashicorp/boundary database migrate -config /boundary/config.hcl
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
  hashicorp/boundary
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
  hashicorp/boundary
```
