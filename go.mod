module github.com/hashicorp/boundary

go 1.16

replace github.com/hashicorp/boundary/api => ./api

replace github.com/hashicorp/boundary/sdk => ./sdk

require (
	github.com/armon/go-metrics v0.3.9
	github.com/bufbuild/buf v0.37.0
	github.com/dhui/dktest v0.3.4
	github.com/fatih/color v1.12.0
	github.com/fatih/structs v1.1.0
	github.com/favadi/protoc-go-inject-tag v1.1.0
	github.com/golang-migrate/migrate/v4 v4.14.1
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.6
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.3.0
	github.com/hashicorp/boundary/api v0.0.16-0.20210811162320-6409d36fca32
	github.com/hashicorp/boundary/sdk v0.0.7-0.20210811172233-d885008bf520
	github.com/hashicorp/cap v0.1.1
	github.com/hashicorp/dawdle v0.4.0
	github.com/hashicorp/dbassert v0.0.0-20200930125617-6218396928df
	github.com/hashicorp/eventlogger v0.1.0
	github.com/hashicorp/go-bexpr v0.1.9
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-20210811210616-0aaf8919030a
	github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2 v2.0.0-20210811211723-df21fc5f6a57
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.1
	github.com/hashicorp/go-secure-stdlib/configutil/v2 v2.0.0-20210811212036-e8613569ca1f
	github.com/hashicorp/go-secure-stdlib/gatedwriter v0.1.1
	github.com/hashicorp/go-secure-stdlib/kv-builder v0.1.1
	github.com/hashicorp/go-secure-stdlib/listenerutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.1
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/password v0.1.1
	github.com/hashicorp/go-secure-stdlib/reloadutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/hashicorp/go-uuid v1.0.2
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.1.1
	github.com/iancoleman/strcase v0.1.3
	github.com/jefferai/keyring v1.1.7-0.20210105022822-8749b3d9ce79
	github.com/jinzhu/gorm v1.9.16
	github.com/jinzhu/now v1.1.1 // indirect
	github.com/json-iterator/go v1.1.10 // indirect
	github.com/kr/pretty v0.2.1
	github.com/kr/text v0.2.0
	github.com/lib/pq v1.10.2
	github.com/mattn/go-colorable v0.1.8
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/mitchellh/cli v1.1.2
	github.com/mitchellh/go-wordwrap v1.0.1
	github.com/mitchellh/gox v1.0.1
	github.com/mitchellh/mapstructure v1.4.1
	github.com/mitchellh/pointerstructure v1.2.0
	github.com/mr-tron/base58 v1.2.0
	github.com/oligot/go-mod-upgrade v0.6.1
	github.com/ory/dockertest/v3 v3.6.5
	github.com/patrickmn/go-cache v2.1.0+incompatible
	github.com/pires/go-proxyproto v0.5.0
	github.com/pkg/errors v0.9.1
	github.com/posener/complete v1.2.3
	github.com/spf13/cobra v1.1.1 // indirect
	github.com/stretchr/testify v1.7.0
	github.com/zalando/go-keyring v0.1.1
	go.uber.org/atomic v1.8.0
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c
	golang.org/x/term v0.0.0-20210503060354-a79de5458b56
	golang.org/x/tools v0.1.3
	google.golang.org/genproto v0.0.0-20210319143718-93e7006c17a6
	google.golang.org/grpc v1.38.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.4.0 // indirect
	mvdan.cc/gofumpt v0.1.1
	nhooyr.io/websocket v1.8.7
)
