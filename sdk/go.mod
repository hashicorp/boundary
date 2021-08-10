module github.com/hashicorp/boundary/sdk

go 1.16

require (
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-20210810171353-2a298deaeb2d
	github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2 v2.0.0-20210810171353-2a298deaeb2d
	github.com/hashicorp/go-secure-stdlib/configutil/v2 v2.0.0-20210810171518-2e89ea49c1ea
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.7.0
	google.golang.org/protobuf v1.27.1
)
