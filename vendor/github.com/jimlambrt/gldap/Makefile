.PHONY: test
test:
	go test -race -count=1 ./... 

.PHONY: build
build:
	go build ./... 

.PHONY: tools
tools:
	go generate -tags tools tools/tools.go
	go install github.com/hashicorp/copywrite@v0.16.6

.PHONY: fmt
fmt:
	gofumpt -w $$(find . -name '*.go')

.PHONY: gen
gen: fmt copywrite

# coverage-diff will run a new coverage report and check coverage.log to see if
# the coverage has changed.  
.PHONY: coverage-diff
coverage-diff: 
	cd coverage && \
	./coverage.sh && \
	./cov-diff.sh coverage.log && \
	if ./cov-diff.sh ./coverage.log; then git restore coverage.log; fi

# coverage will generate a report, badge and log.  when you make changes, run
# this and check in the changes to publish a new/latest coverage report and
# badge. 
.PHONY: coverage
coverage: 
	cd coverage && \
	./coverage.sh && \
	if ./cov-diff.sh ./coverage.log; then git restore coverage.log; fi

.PHONY: copywrite
copywrite:
	copywrite headers