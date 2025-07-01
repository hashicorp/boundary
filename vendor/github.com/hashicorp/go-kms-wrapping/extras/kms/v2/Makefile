.PHONY: tools
tools:
	go generate -tags tools tools/tools.go

.PHONY: fmt
fmt:
	gofumpt -w $$(find . -name '*.go')

.PHONY: test
test: 
	go test -race -count=1 ./...

.PHONY: test-all
test-all: test-sqlite test-postgres

.PHONY: test-sqlite
test-sqlite:
	DB_DIALECT=sqlite go test -race -count=1 ./...

.PHONY: test-postgres
test-postgres:
	##############################################################
	# this test is dependent on first running: docker-compose up
	##############################################################
	DB_DIALECT=postgres DB_DSN="postgresql://go_db:go_db@localhost:9920/go_db?sslmode=disable"  go test -race -count=1 ./...
