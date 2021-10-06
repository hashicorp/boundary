module github.com/hashicorp/boundary

go 1.16

replace github.com/hashicorp/boundary/api => ./api

replace github.com/hashicorp/boundary/sdk => ./sdk

replace github.com/hashicorp/boundary/plugins => ./plugins

// tmp use of local clone as we understand any required upstream PRs to
// compatibility.
replace gorm.io/gorm => github.com/hashicorp/gorm v0.0.2

require (
	github.com/Azure/azure-sdk-for-go v57.4.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.21 // indirect
	github.com/Azure/go-autorest/autorest/azure/auth v0.5.8 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/armon/go-metrics v0.3.9
	github.com/aws/aws-sdk-go v1.40.44 // indirect
	github.com/bufbuild/buf v0.37.0
	github.com/dhui/dktest v0.3.4 // indirect
	github.com/fatih/color v1.12.0
	github.com/fatih/structs v1.1.0
	github.com/favadi/protoc-go-inject-tag v1.3.0
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.6.0
	github.com/hashicorp/boundary/api v0.0.19
	github.com/hashicorp/boundary/plugins v0.0.0-20211006012628-8453801cc56e
	github.com/hashicorp/boundary/sdk v0.0.12-0.20211006012547-dc41f8dbc15c
	github.com/hashicorp/cap v0.1.1
	github.com/hashicorp/dawdle v0.4.0
	github.com/hashicorp/dbassert v0.0.0-20210708202608-ecf920cf1ed8
	github.com/hashicorp/eventlogger v0.1.0
	github.com/hashicorp/eventlogger/filters/encrypt v0.1.4-0.20210928205053-80364fba97eb
	github.com/hashicorp/go-bexpr v0.1.10
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-kms-wrapping v0.6.6
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/awsutil v0.1.4 // indirect
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.1
	github.com/hashicorp/go-secure-stdlib/configutil v0.1.2
	github.com/hashicorp/go-secure-stdlib/gatedwriter v0.1.1
	github.com/hashicorp/go-secure-stdlib/kv-builder v0.1.1
	github.com/hashicorp/go-secure-stdlib/listenerutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.1
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/password v0.1.1
	github.com/hashicorp/go-secure-stdlib/reloadutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.1.1
	github.com/hashicorp/vault/sdk v0.2.1
	github.com/iancoleman/strcase v0.2.0
	github.com/jackc/pgconn v1.10.0
	github.com/jackc/pgx/v4 v4.11.0
	github.com/jefferai/keyring v1.1.7-0.20210105022822-8749b3d9ce79
	github.com/kr/pretty v0.3.0
	github.com/kr/text v0.2.0
	github.com/mattn/go-colorable v0.1.8
	github.com/mitchellh/cli v1.1.2
	github.com/mitchellh/copystructure v1.2.0
	github.com/mitchellh/go-wordwrap v1.0.1
	github.com/mitchellh/gox v1.0.1
	github.com/mitchellh/mapstructure v1.4.2
	github.com/mitchellh/pointerstructure v1.2.0
	github.com/mr-tron/base58 v1.2.0
	github.com/oligot/go-mod-upgrade v0.6.1
	github.com/ory/dockertest/v3 v3.7.0
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pires/go-proxyproto v0.6.1
	github.com/pkg/errors v0.9.1
	github.com/posener/complete v1.2.3
	github.com/ryanuber/go-glob v1.0.0
	github.com/spf13/cobra v1.1.1 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/zalando/go-keyring v0.1.1
	go.uber.org/atomic v1.9.0
	golang.org/x/crypto v0.0.0-20210915214749-c084706c2272
	golang.org/x/sys v0.0.0-20210917161153-d61c044b1678
	golang.org/x/term v0.0.0-20210916214954-140adaaadfaf
	golang.org/x/tools v0.1.6
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20210903162649-d08c68adba83
	google.golang.org/grpc v1.40.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.27.1
	gorm.io/driver/postgres v1.1.0
	gorm.io/gorm v1.21.14
	mvdan.cc/gofumpt v0.1.1
	nhooyr.io/websocket v1.8.7
)
