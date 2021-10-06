# Dep Owners

This file is kept here for coordination within the Boundary team. It indicates
who is responsible for doing due diligence and approving a dep update during
dependency upgrade cycles.

## Deps with No Owners

These deps have no specific owner because they are transitive (and will be
reviewed with updates to the direct dependency); because they are for upcoming
features but not directly exposed to user-facing aspects of the project; or
because all changes to the dep are made by one of the Boundary team members in
the first place.

* github.com/armon/go-metrics
* github.com/go-swagger/go-swagger
* github.com/golang-sql/civil
* github.com/hashicorp/boundary/api
* github.com/hashicorp/boundary/sdk
* github.com/kr/text
* github.com/oligot/go-mod-upgrade
* github.com/pires/go-proxyproto
* mvdan.cc/gofumpt
* golang.org/x/crypto
* golang.org/x/sys
* golang.org/x/tools
* google.golang.org/genproto

## Deps with Owners

* github.com/bufbuild/buf
    * Jeff
    * Todd
* github.com/dhui/dktest
    * Todd
    * Louis
* github.com/fatih/color
    * Jeff
    * Sarah
* github.com/favadi/protoc-go-inject-tag
    * Jim
    * Todd
* github.com/golang-migrate/migrate/v4
    * Jim
    * Mike
* github.com/golang/protobuf
    * Jeff
    * Todd
* github.com/google/go-cmp
    * Todd
    * Sarah
* github.com/grpc-ecosystem/grpc-gateway/v2
    * Todd
    * Jeff
* github.com/hashicorp/dbassert
    * Jim
* github.com/hashicorp/errwrap
    * Jeff
* github.com/hashicorp/go-bexpr
    * Jeff
* github.com/hashicorp/go-cleanhttp
    * Jeff
* github.com/hashicorp/go-hclog
    * Jeff
* github.com/hashicorp/go-kms-wrapping
    * Jeff
* github.com/hashicorp/go-multierror
    * Jeff
* github.com/hashicorp/go-retryablehttp
    * Jeff
* github.com/hashicorp/go-uuid
    * Jeff
* github.com/hashicorp/hcl
    * Jeff
* github.com/hashicorp/shared-secure-libs
    * Jeff
* github.com/hashicorp/vault/sdk
    * Jeff
* github.com/iancoleman/strcase
    * Jeff
* github.com/jefferai/keyring
    * Jeff
* github.com/jinzhu/gorm
    * Jim
    * Mike
* github.com/kr/pretty
    * Jeff
* github.com/lib/pq
  * Jim
  * Mike
* github.com/jackc/pgx
    * Jim
    * Mike
* github.com/mattn/go-colorable
    * Jeff
    * Sarah
* github.com/mitchellh/cli
    * Jeff
    * Sarah
* github.com/mitchellh/go-wordwrap
    * Jeff
* github.com/mitchellh/gox
    * Jeff
* github.com/mitchellh/mapstructure
    * Jeff
    * Louis
* github.com/mr-tron/base58
    * Jeff
    * Sarah
* github.com/ory/dockertest/v3 ([DO NOT UPDATE PAST v3.6.0!!!](https://github.com/ory/dockertest/issues/232))
    * Jeff
* github.com/patrickmn/go-cache
    * Jeff
    * Sarah
* github.com/pkg/errors
    * Louis
    * Sarah
* github.com/posener/complete
    * Jeff
    * Sarah
* github.com/stretchr/testify
    * Mike
    * Jim
* github.com/zalando/go-keyring
    * Jeff
    * Louis
* go.uber.org/atomic
    * Jeff
* google.golang.org/grpc
    * Todd
    * Jeff
* google.golang.org/grpc/cmd/protoc-gen-go-grpc
    * Todd
    * Jeff
* google.golang.org/protobuf
    * Todd
    * Jeff
* nhooyr.io/websocket
    * Jeff
    * Jim
