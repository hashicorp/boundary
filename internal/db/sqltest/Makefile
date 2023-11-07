all: test

CWD := $(shell pwd)

# Version of postgres docker image for test database
PG_DOCKER_TAG ?= 13-alpine
# Version of pg_tap docker image
PG_TAP_DOCKER_TAG ?= 13
SQL_TEST_DB_PORT ?=
DOCKER_ARGS ?=
ifneq ($(strip $(SQL_TEST_DB_PORT)),)
	DOCKER_ARGS += -p $(SQL_TEST_DB_PORT):5432
endif


# Pass through options to pg_prove
# See: https://pgtap.org/pg_prove.html
PROVE_OPTS ?=

TESTS ?= tests/setup/*.sql \
		 tests/org/*.sql \
		 tests/wh/*/*.sql \
		 tests/sentinel/*.sql \
		 tests/credential/*/*.sql \
		 tests/session/*.sql \
		 tests/account/*/*.sql \
		 tests/target/*.sql \
		 tests/controller/*.sql \
		 tests/hcp/*/*.sql \
		 tests/census/*.sql \
		 tests/kms/*.sql \
		 tests/storage/*.sql \
		 tests/domain/*.sql \
		 tests/history/*.sql \
		 tests/recording/*.sql \
		 tests/auth/*/*.sql \
		 tests/purge/*sql \
		 tests/index/*sql

POSTGRES_DOCKER_IMAGE_BASE ?= postgres

POSTGRES_DOCKER_IMAGE := $(POSTGRES_DOCKER_IMAGE_BASE):$(PG_DOCKER_TAG)

PG_TAP_DOCKER_IMAGE_BASE ?= hashicorpboundary/pgtap
PG_TAP_DOCKER_IMAGE := $(PG_TAP_DOCKER_IMAGE_BASE):$(PG_TAP_DOCKER_TAG)

SQL_TEST_CONTAINER_NAME ?= boundary-sql-tests


# re-write paths for docker
dockerized_tests = $(patsubst tests/%,/test/%,$(TESTS))

test:
	@echo Using $(POSTGRES_DOCKER_IMAGE)
	@echo Using $(PG_TAP_DOCKER_IMAGE)
	@docker run -d \
		--name $(SQL_TEST_CONTAINER_NAME) \
		$(DOCKER_ARGS) \
		-e POSTGRES_PASSWORD=boundary \
		-e POSTGRES_USER=boundary \
		-e POSTGRES_DB=boundary \
		-v "$(CWD)/../schema/migrations":/migrations \
		-v "$(CWD)/initdb.d":/docker-entrypoint-initdb.d/ \
		$(POSTGRES_DOCKER_IMAGE)
	@docker run --rm \
		--name test \
		--link $(SQL_TEST_CONTAINER_NAME):db \
		-e DATABASE=boundary \
		-e HOST=db \
		-e PORT=5432 \
		-e USER=boundary \
		-e PASSWORD=boundary \
		-e TESTS="$(PROVE_OPTS) $(dockerized_tests)" \
		-v "$(CWD)/tests":/test \
		$(PG_TAP_DOCKER_IMAGE); \
		(ret=$$?; docker stop $(SQL_TEST_CONTAINER_NAME) &>/dev/null && docker logs $(SQL_TEST_CONTAINER_NAME) && docker rm -v $(SQL_TEST_CONTAINER_NAME) &>/dev/null && exit $$ret)

database-up:
	@echo Using $(POSTGRES_DOCKER_IMAGE)
	@docker run -d \
		--name $(SQL_TEST_CONTAINER_NAME) \
		$(DOCKER_ARGS) \
		-e POSTGRES_PASSWORD=boundary \
		-e POSTGRES_USER=boundary \
		-e POSTGRES_DB=boundary \
		-v "$(CWD)/../schema/migrations":/migrations \
		-v "$(CWD)/initdb.d":/docker-entrypoint-initdb.d/ \
		$(POSTGRES_DOCKER_IMAGE)
ifdef SQL_TEST_DB_PORT
	@echo "Test database available at:  postgres://boundary:boundary@localhost:$(SQL_TEST_DB_PORT)/boundary?sslmode=disable"
endif

run-tests:
	@echo Using $(PG_TAP_DOCKER_IMAGE)
	@docker run -it --rm \
		--name test \
		--link $(SQL_TEST_CONTAINER_NAME):db \
		-e DATABASE=boundary \
		-e HOST=db \
		-e PORT=5432 \
		-e USER=boundary \
		-e PASSWORD=boundary \
		-e TESTS="$(PROVE_OPTS) $(dockerized_tests)" \
		-v "$(CWD)/tests":/test \
		$(PG_TAP_DOCKER_IMAGE)

clean:
	docker stop $(SQL_TEST_CONTAINER_NAME) || true
	docker rm -v $(SQL_TEST_CONTAINER_NAME) || true

.PHONY: all clean test database-up run-tests
