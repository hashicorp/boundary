module github.com/hashicorp/boundary/api

go 1.15

require (
	github.com/fatih/structs v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-20211004181108-59533a548d29
	github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2 v2.0.0-20211004181156-d323e1064fea
	github.com/hashicorp/go-retryablehttp v0.6.8
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.7.0
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e
	google.golang.org/grpc v1.38.0
	google.golang.org/protobuf v1.27.1
)
