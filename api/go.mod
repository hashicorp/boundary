module github.com/hashicorp/boundary/api

go 1.15

replace github.com/hashicorp/boundary/sdk => ../sdk

require (
	github.com/fatih/structs v1.1.0
	github.com/hashicorp/boundary/sdk v0.0.2
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-kms-wrapping v0.5.16
	github.com/hashicorp/go-retryablehttp v0.6.7
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/stretchr/testify v1.6.1
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	google.golang.org/grpc v1.32.0
)
