all: docker-build

CWD := $(shell pwd)
DOCKER_ARGS ?= -d

REGISTRY_NAME?=docker.io/hashicorpboundary
IMAGE_NAME=postgres
IMAGE_TAG ?= $(REGISTRY_NAME)/$(IMAGE_NAME):11-alpine
PG_OPTS ?=
TEST_DB_PORT ?= 5432
TEST_CONTAINER_NAME ?= boundary-sql-tests

# Generate targets from dockerfiles
dockerfiles = $(wildcard Dockerfile.*)
docker-builds = $(patsubst Dockerfile.%,%-build, $(dockerfiles))
docker-publishes = $(patsubst Dockerfile.%,%-publish, $(dockerfiles))

${docker-builds}: %-build:
	docker build -t $(REGISTRY_NAME)/$(IMAGE_NAME):$* -f Dockerfile.$* .

docker-build: ${docker-builds}

docker-publish: ${docker-publishes}

${docker-publishes}: %-publish:
	docker push $(REGISTRY_NAME)/$(IMAGE_NAME):$*

database-up:
	@echo "Using image:                       $(IMAGE_TAG)"
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
		$(IMAGE_TAG) \
		-c 'config_file=/etc/postgresql/postgresql.conf' \
		$(PG_OPTS) 1> /dev/null
	@echo "Container name:                    $(TEST_CONTAINER_NAME)"
	@echo "Test database available at:        127.0.0.1:$(TEST_DB_PORT)"
	@echo "For database logs run:"
	@echo "    docker logs $(TEST_CONTAINER_NAME)"
clean:
	docker stop $(TEST_CONTAINER_NAME) || true
	docker rm -v $(TEST_CONTAINER_NAME) || true

.PHONY: all docker-build database-up ${docker-builds} ${docker-publishes} clean
