all: docker-build

CWD := $(shell pwd)
DOCKER_ARGS ?= -d

DOCKER_MIRROR?=docker.io
REGISTRY_NAME?=hashicorpboundary
TEST_IMAGE_NAME=postgres
TEST_IMAGE_TAG ?= $(DOCKER_MIRROR)/$(REGISTRY_NAME)/$(TEST_IMAGE_NAME):12-alpine
PG_OPTS ?=
TEST_DB_PORT ?= 5432
TEST_CONTAINER_NAME ?= boundary-sql-tests

# Generate targets from dockerfiles
dockerfiles = $(wildcard Dockerfile.*)
docker-buildxs = $(patsubst Dockerfile.%,%-buildx, $(dockerfiles))
docker-load-buildxs = $(patsubst Dockerfile.%,%-load-buildx, $(dockerfiles))

docker-build: ${docker-buildxs}

${docker-buildxs}: %-buildx:
	docker buildx build \
		--platform linux/amd64,linux/arm64 \
		--push \
		-t $(DOCKER_MIRROR)/$(REGISTRY_NAME)/$(TEST_IMAGE_NAME):$* \
		-f Dockerfile.$* .

docker-load: ${docker-load-buildxs}

${docker-load-buildxs}: %-load-buildx:
	docker buildx build \
		--load \
		-t $(DOCKER_MIRROR)/$(REGISTRY_NAME)/$(TEST_IMAGE_NAME):$* \
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
		-v "$(CWD)/benchmark_dumps":/benchmark_dumps \
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

generate-database-dumps:
	BOUNDARY_DB_TEST_GENERATE_SESSION_BENCHMARK_TEMPLATE_DUMPS=1 go test \
		-v \
		-run '^TestGenerateSessionBenchmarkTemplateDumps$$' \
		--timeout=1000h \
		-count=1 \
		../

.PHONY: all docker-build database-up ${docker-buildxs} ${docker-load-buildxs} generate-database-dumps clean
