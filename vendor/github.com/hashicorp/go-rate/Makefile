GO_PATH = $(shell go env GOPATH)

.PHONY: all
all: test

.PHONY: tools
tools: golangci-lint
	go install github.com/hashicorp/copywrite@v0.15.0
	go install mvdan.cc/gofumpt@v0.3.1
	go install golang.org/x/perf/cmd/benchstat@latest

# golangci-lint recommends installing the binary directly, instead of using go get
# See the note: https://golangci-lint.run/usage/install/#install-from-source
.PHONY: golangci-lint
golangci-lint:
	$(eval GOLINT_INSTALLED := $(shell which golangci-lint))

	if [ "$(GOLINT_INSTALLED)" = "" ]; then \
		curl -sSfL \
			https://raw.githubusercontent.com/golangci/golangci-lint/9a8a056e9fe49c0e9ed2287aedce1022c79a115b/install.sh | sh -s -- -b $(GO_PATH)/bin v1.52.2; \
	fi;

.PHONY: test
test:
	go test -race -v ./...

.PHONY: cover-html
cover-html:
	go test -race -v -cover -coverprofile=.coverage ./... && \
		go tool cover -html=.coverage && \
		rm -f .coverage

.PHONY: bench
bench:
	go test -timeout=120m -v -bench=. -count=1 -run=^#

.PHONY: copywrite
copywrite:
	copywrite headers

.PHONY: fmt
fmt:
	gofumpt -w .

.PHONY: lint
lint:
	golangci-lint run

.PHONY: gen
gen: copywrite fmt
