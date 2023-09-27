module github.com/hashicorp/boundary/api

go 1.19

replace github.com/hashicorp/boundary/sdk => ../sdk

require (
	github.com/hashicorp/boundary/sdk v0.0.37
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.10-0.20230601143830-08d524b564ba
	github.com/hashicorp/go-retryablehttp v0.7.2
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7
	github.com/hashicorp/go-uuid v1.0.3
	github.com/mitchellh/mapstructure v1.5.0
	github.com/mr-tron/base58 v1.2.0
	github.com/stretchr/testify v1.8.4
	go.uber.org/atomic v1.11.0
	golang.org/x/time v0.3.0
	google.golang.org/grpc v1.55.0
	google.golang.org/protobuf v1.30.0
	nhooyr.io/websocket v1.8.7
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/fatih/color v1.15.0 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/eventlogger v0.1.2-0.20230428153751-cca445805f24 // indirect
	github.com/hashicorp/eventlogger/filters/encrypt v0.1.8-0.20230428153751-cca445805f24 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-secure-stdlib/configutil/v2 v2.0.10 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.2 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-isatty v0.0.19 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/pointerstructure v1.2.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	go.uber.org/goleak v1.1.10 // indirect
	golang.org/x/crypto v0.9.0 // indirect
	golang.org/x/tools v0.6.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20230530153820-e85fd2cbaebc // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20230530153820-e85fd2cbaebc // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
