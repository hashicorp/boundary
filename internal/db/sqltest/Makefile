all: test

CWD := $(shell pwd)

# Version of postgres docker image for test database
PG_DOCKER_TAG ?= 13-alpine
# Version of pg_tap docker image
PG_TAP_DOCKER_TAG ?= pg13

# Pass through options to pg_prove
# See: https://pgtap.org/pg_prove.html
PROVE_OPTS ?=

TESTS ?= tests/setup/*.sql \
		 tests/wh/*/*.sql

POSTGRES_DOCKER_IMAGE_BASE ?= postgres

POSTGRES_DOCKER_IMAGE := $(POSTGRES_DOCKER_IMAGE_BASE):$(PG_DOCKER_TAG)

PG_TAP_DOCKER_IMAGE_BASE ?= subzerocloud/pgtap
PG_TAP_DOCKER_IMAGE := $(PG_TAP_DOCKER_IMAGE_BASE):$(PG_TAP_DOCKER_TAG)


# re-write paths for docker
dockerized_tests = $(patsubst tests/%,/test/%,$(TESTS))

test:
	@echo Using $(POSTGRES_DOCKER_IMAGE)
	@echo Using $(PG_TAP_DOCKER_IMAGE)
	@docker run -d \
		--name boundary-sql-tests \
		-e POSTGRES_PASSWORD=boundary \
		-e POSTGRES_USER=boundary \
		-e POSTGRES_DB=boundary \
		-v "$(CWD)/../schema/migrations":/migrations \
		-v "$(CWD)/initdb.d":/docker-entrypoint-initdb.d/ \
		$(POSTGRES_DOCKER_IMAGE)
	@docker run -it --rm \
		--name test \
		--link boundary-sql-tests:db \
		-e DATABASE=boundary \
		-e HOST=db \
		-e PORT=5432 \
		-e USER=boundary \
		-e PASSWORD=boundary \
		-e TESTS="$(PROVE_OPTS) $(dockerized_tests)" \
		-v "$(CWD)/tests":/test \
		$(PG_TAP_DOCKER_IMAGE); \
		(ret=$$?; docker stop boundary-sql-tests &>/dev/null && docker rm -v boundary-sql-tests &>/dev/null && exit $$ret)

database-up:
	@echo Using $(POSTGRES_DOCKER_IMAGE)
	@docker run -d \
		--name boundary-sql-tests \
		-e POSTGRES_PASSWORD=boundary \
		-e POSTGRES_USER=boundary \
		-e POSTGRES_DB=boundary \
		-v "$(CWD)/../schema/migrations":/migrations \
		-v "$(CWD)/initdb.d":/docker-entrypoint-initdb.d/ \
		$(POSTGRES_DOCKER_IMAGE)

run-tests:
	@echo Using $(PG_TAP_DOCKER_IMAGE)
	@docker run -it --rm \
		--name test \
		--link boundary-sql-tests:db \
		-e DATABASE=boundary \
		-e HOST=db \
		-e PORT=5432 \
		-e USER=boundary \
		-e PASSWORD=boundary \
		-e TESTS="$(PROVE_OPTS) $(dockerized_tests)" \
		-v "$(CWD)/tests":/test \
		$(PG_TAP_DOCKER_IMAGE)

clean:
	docker stop boundary-sql-tests || true
	docker rm -v boundary-sql-tests || true

.PHONY: all clean test database-up run-tests
