module github.com/hashicorp/boundary

go 1.14

replace github.com/hashicorp/boundary/api => ./api

replace github.com/hashicorp/boundary/sdk => ./sdk

require (
	github.com/armon/go-metrics v0.3.4
	github.com/bufbuild/buf v0.24.0
	github.com/fatih/color v1.9.0
	github.com/favadi/protoc-go-inject-tag v1.1.0
	github.com/go-bindata/go-bindata/v3 v3.1.3
	github.com/go-swagger/go-swagger v0.25.0
	github.com/golang-migrate/migrate/v4 v4.13.0
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe
	github.com/golang/protobuf v1.4.2
	github.com/google/go-cmp v0.5.2
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.0.0-beta.5
	github.com/hashicorp/boundary/api v0.0.1
	github.com/hashicorp/boundary/sdk v0.0.1
	github.com/hashicorp/dbassert v0.0.0-20200930125617-6218396928df
	github.com/hashicorp/errwrap v1.1.0
	github.com/hashicorp/go-cleanhttp v0.5.1
	github.com/hashicorp/go-hclog v0.14.1
	github.com/hashicorp/go-kms-wrapping v0.5.16
	github.com/hashicorp/go-multierror v1.1.0
	github.com/hashicorp/go-retryablehttp v0.6.7
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/shared-secure-libs v0.0.2
	github.com/hashicorp/vault/sdk v0.1.14-0.20200916184745-5576096032f8
	github.com/iancoleman/strcase v0.1.2
	github.com/jackc/pgx/v4 v4.9.0
	github.com/jinzhu/gorm v1.9.16
	github.com/kr/pretty v0.2.1
	github.com/kr/text v0.2.0
	github.com/lib/pq v1.8.0
	github.com/mattn/go-colorable v0.1.8
	github.com/mitchellh/cli v1.1.2
	github.com/mitchellh/go-wordwrap v1.0.1
	github.com/mitchellh/gox v1.0.1
	github.com/mr-tron/base58 v1.2.0
	github.com/oligot/go-mod-upgrade v0.2.1
	github.com/ory/dockertest/v3 v3.6.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pires/go-proxyproto v0.2.0
	github.com/pkg/errors v0.9.1
	github.com/posener/complete v1.2.3
	github.com/stretchr/testify v1.6.1
	github.com/zalando/go-keyring v0.1.0
	go.uber.org/atomic v1.7.0
	golang.org/x/crypto v0.0.0-20201002170205-7f63de1d35b0
	golang.org/x/tools v0.0.0-20201009032223-96877f285f7e
	google.golang.org/genproto v0.0.0-20201009135657-4d944d34d83c
	google.golang.org/grpc v1.32.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v0.0.0-20200527211525-6c9e30c09db2
	google.golang.org/protobuf v1.25.0
	nhooyr.io/websocket v1.8.6
)
