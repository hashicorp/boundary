all: docker-build

CWD := $(shell pwd)
DOCKER_ARGS ?= -d

REGISTRY_NAME?=docker.io/hashicorpboundary
TEST_IMAGE_NAME=postgres
TEST_IMAGE_TAG ?= $(REGISTRY_NAME)/$(TEST_IMAGE_NAME):11-alpine
PG_OPTS ?=
TEST_DB_PORT ?= 5432
TEST_CONTAINER_NAME ?= boundary-sql-tests

# Generate targets from dockerfiles
dockerfiles = $(wildcard Dockerfile.*)
docker-buildxs = $(patsubst Dockerfile.%,%-buildx, $(dockerfiles))

# Before running this target a builder instance needs to be setup, ie:
#  docker buildx create --driver docker-container --use
docker-build: ${docker-buildxs}

${docker-buildxs}: %-buildx:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--push \
		-t $(REGISTRY_NAME)/$(TEST_IMAGE_NAME):$* \
		-f Dockerfile.$* .

database-up:
	@echo "Using image:                       $(TEST_IMAGE_TAG)"
	@echo "Additional postgres configuration: $(PG_OPTS)"
	@docker run \
		$(DOCKER_ARGS) \
		--name $(TEST_CONTAINER_NAME) \
		-p $(TEST_DB_PORT):5432 \
		-e POSTGRES_PASSWORD=boundary \
		-e POSTGRES_USER=boundary \
		-e POSTGRES_DB=boundary \
		-e PGDATA=/pgdata \
		--mount type=tmpfs,destination=/pgdata \
		-v "$(CWD)/../../../internal/db/schema/migrations":/migrations \
		$(TEST_IMAGE_TAG) \
		-c 'config_file=/etc/postgresql/postgresql.conf' \
		$(PG_OPTS) 1> /dev/null
	@echo "Container name:                    $(TEST_CONTAINER_NAME)"
	@echo "Test database available at:        127.0.0.1:$(TEST_DB_PORT)"
	@echo "For database logs run:"
	@echo "    docker logs $(TEST_CONTAINER_NAME)"
clean:
	docker stop $(TEST_CONTAINER_NAME) || true
	docker rm -v $(TEST_CONTAINER_NAME) || true

.PHONY: all docker-build database-up ${docker-buildxs} clean
