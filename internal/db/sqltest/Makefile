all: test

CWD := $(shell pwd)

PG_VERSION ?= 11

test:
	@docker run -d \
		--name boundary-sql-tests \
		-e POSTGRES_PASSWORD=boundary \
      	-e POSTGRES_USER=boundary \
      	-e POSTGRES_DB=boundary \
		-v "$(CWD)/../schema/migrations/postgres":/migrations \
		-v "$(CWD)/initdb.d":/docker-entrypoint-initdb.d/ \
		postgres:$(PG_VERSION)-alpine
	@docker run -it --rm \
		--name test \
		--link boundary-sql-tests:db \
		-e DATABASE=boundary \
		-e HOST=db \
		-e PORT=5432 \
		-e USER=boundary \
		-e PASSWORD=boundary \
		-e TESTS="/test/setup/*.sql /test/*.sql" \
		-v "$(CWD)/tests":/test \
		subzerocloud/pgtap:pg$(PG_VERSION); \
		(ret=$$?; docker stop boundary-sql-tests &>/dev/null && docker rm boundary-sql-tests &>/dev/null && exit $$ret)

clean:
	docker stop boundary-sql-tests || true
	docker rm boundary-sql-tests || true

.PHONY: all clean test
