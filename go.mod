module github.com/hashicorp/boundary

go 1.23.1

replace github.com/hashicorp/boundary/api => ./api

replace github.com/hashicorp/boundary/sdk => ./sdk

require (
	github.com/fatih/color v1.17.0
	github.com/fatih/structs v1.1.0
	github.com/favadi/protoc-go-inject-tag v1.4.0
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/golang-migrate/migrate/v4 v4.17.0
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9
	github.com/google/go-cmp v0.6.0
	github.com/grpc-ecosystem/go-grpc-middleware v1.4.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.19.1
	github.com/hashicorp/boundary/api v0.0.50
	github.com/hashicorp/boundary/sdk v0.0.48
	github.com/hashicorp/cap v0.5.1-0.20240315182732-faa330bfb8df
	github.com/hashicorp/dawdle v0.5.0
	github.com/hashicorp/eventlogger v0.2.9
	github.com/hashicorp/eventlogger/filters/encrypt v0.1.8-0.20231208142215-efdb51ec090d
	github.com/hashicorp/go-bexpr v0.1.13
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.6.3
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.17-0.20240313190905-91d44aa8e360
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.7
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-secure-stdlib/configutil/v2 v2.0.11
	github.com/hashicorp/go-secure-stdlib/gatedwriter v0.1.1
	github.com/hashicorp/go-secure-stdlib/kv-builder v0.1.2
	github.com/hashicorp/go-secure-stdlib/listenerutil v0.1.9
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.3
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.8
	github.com/hashicorp/go-secure-stdlib/password v0.1.3
	github.com/hashicorp/go-secure-stdlib/pluginutil/v2 v2.0.6
	github.com/hashicorp/go-secure-stdlib/reloadutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/go-sockaddr v1.0.6
	github.com/hashicorp/go-uuid v1.0.3
	github.com/hashicorp/hcl v1.0.1-vault-5
	github.com/hashicorp/vault/api v1.12.0
	github.com/iancoleman/strcase v0.3.0
	github.com/jackc/pgconn v1.14.3
	github.com/jefferai/keyring v1.1.7-0.20220316160357-58a74bb55891
	github.com/kr/pretty v0.3.1
	github.com/kr/text v0.2.0
	github.com/mattn/go-colorable v0.1.13
	github.com/mitchellh/cli v1.1.5
	github.com/mitchellh/copystructure v1.2.0
	github.com/mitchellh/go-wordwrap v1.0.1
	github.com/mitchellh/mapstructure v1.5.0
	github.com/mitchellh/pointerstructure v1.2.1
	github.com/mr-tron/base58 v1.2.0
	github.com/oligot/go-mod-upgrade v0.9.1
	github.com/ory/dockertest/v3 v3.10.0
	github.com/pires/go-proxyproto v0.7.0
	github.com/pkg/errors v0.9.1 // indirect
	github.com/posener/complete v1.2.3
	github.com/prometheus/client_golang v1.18.0
	github.com/ryanuber/go-glob v1.0.0
	github.com/stretchr/testify v1.9.0
	github.com/zalando/go-keyring v0.2.3
	go.uber.org/atomic v1.11.0
	golang.org/x/crypto v0.25.0
	golang.org/x/sync v0.7.0
	golang.org/x/sys v0.22.0
	golang.org/x/term v0.22.0
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d
	google.golang.org/genproto v0.0.0-20240205150955-31a09d347014
	google.golang.org/grpc v1.61.1
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.3.0
	google.golang.org/protobuf v1.34.2
	gorm.io/driver/postgres v1.5.9
	gorm.io/gorm v1.25.11 // indirect
	mvdan.cc/gofumpt v0.5.0
	nhooyr.io/websocket v1.8.10
)

require github.com/hashicorp/go-dbw v0.1.5-0.20240909162114-6cee92b3da36

require (
	github.com/DATA-DOG/go-sqlmock v1.5.2
	github.com/cenkalti/backoff/v4 v4.2.1
	github.com/creack/pty v1.1.21
	github.com/glebarez/sqlite v1.10.0
	github.com/golang/protobuf v1.5.3
	github.com/hashicorp/cap/ldap v0.0.0-20240206183135-ed8f24513744
	github.com/hashicorp/dbassert v0.0.0-20231012105025-1bc1bd88e22b
	github.com/hashicorp/go-kms-wrapping/extras/kms/v2 v2.0.0-20231219183231-6bac757bb482
	github.com/hashicorp/go-rate v0.0.0-20231204194614-cc8d401f70ab
	github.com/hashicorp/go-version v1.6.0
	github.com/hashicorp/nodeenrollment v0.2.13
	github.com/jackc/pgx/v5 v5.6.0
	github.com/jimlambrt/gldap v0.1.10
	github.com/kelseyhightower/envconfig v1.4.0
	github.com/miekg/dns v1.1.58
	github.com/mikesmitty/edkey v0.0.0-20170222072505-3356ea4e686a
	github.com/sevlyar/go-daemon v0.1.6
	golang.org/x/exp v0.0.0-20240205201215-2c58cdc269a3
	golang.org/x/net v0.25.0
	google.golang.org/genproto/googleapis/api v0.0.0-20240205150955-31a09d347014
)

require (
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/mattn/go-sqlite3 v1.14.22 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	modernc.org/libc v1.41.0 // indirect
	modernc.org/mathutil v1.6.0 // indirect
	modernc.org/memory v1.7.2 // indirect
	modernc.org/sqlite v1.28.0 // indirect
)

require (
	dario.cat/mergo v1.0.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/distribution/reference v0.5.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/glebarez/go-sqlite v1.22.0 // indirect
	github.com/go-logr/logr v1.4.1 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/jackc/puddle/v2 v2.2.1 // indirect
	github.com/kardianos/osext v0.0.0-20190222173326-2bc1f35cddc0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/sys/user v0.1.0 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.48.0 // indirect
	go.opentelemetry.io/otel v1.23.1 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.23.1 // indirect
	go.opentelemetry.io/otel/metric v1.23.1 // indirect
	go.opentelemetry.io/otel/sdk v1.23.1 // indirect
	go.opentelemetry.io/otel/trace v1.23.1 // indirect
	gorm.io/driver/sqlite v1.5.6 // indirect
)

require (
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/AlecAivazis/survey/v2 v2.3.2 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.2.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.3 // indirect
	github.com/Microsoft/go-winio v0.6.1 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/alessio/shellescape v1.4.2 // indirect
	github.com/apex/log v1.9.0 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/briandowns/spinner v1.16.0 // indirect
	github.com/cenkalti/backoff v2.2.1+incompatible // indirect
	github.com/cenkalti/backoff/v3 v3.2.2 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/containerd/continuity v0.4.3 // indirect
	github.com/coreos/go-oidc/v3 v3.9.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.3 // indirect
	github.com/danieljoos/wincred v1.2.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/docker/cli v25.0.3+incompatible // indirect
	github.com/docker/docker v27.1.1+incompatible
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/dvsekhvalnov/jose2go v1.6.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect
	github.com/go-jose/go-jose/v3 v3.0.3 // indirect
	github.com/go-ldap/ldap/v3 v3.4.6 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-kms-wrapping/plugin/v2 v2.0.7 // indirect
	github.com/hashicorp/go-plugin v1.6.0 // indirect
	github.com/hashicorp/go-secure-stdlib/temperror v0.1.1 // indirect
	github.com/hashicorp/go-secure-stdlib/tlsutil v0.1.3 // indirect
	github.com/hashicorp/mql v0.1.3
	github.com/hashicorp/vault/sdk v0.11.0 // indirect
	github.com/hashicorp/yamux v0.1.1 // indirect
	github.com/huandu/xstrings v1.4.0 // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jefferai/go-libsecret v0.0.0-20210525195240-b53481abef97 // indirect
	github.com/jefferai/isbadcipher v0.0.0-20190226160619-51d2077c035f // indirect
	github.com/jinzhu/gorm v1.9.16 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/mitchellh/go-testing-interface v1.14.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0-rc6 // indirect
	github.com/opencontainers/runc v1.2.0-rc.3 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/prometheus/client_model v0.5.0 // indirect
	github.com/prometheus/common v0.46.0 // indirect
	github.com/prometheus/procfs v0.12.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/sethvargo/go-diceware v0.3.0 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/urfave/cli/v2 v2.3.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xo/dburl v0.23.1 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/oauth2 v0.17.0 // indirect
	golang.org/x/text v0.16.0
	golang.org/x/time v0.5.0 // indirect
	google.golang.org/appengine v1.6.8 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240205150955-31a09d347014 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
