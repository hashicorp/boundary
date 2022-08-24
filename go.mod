module github.com/hashicorp/boundary

go 1.18

replace github.com/hashicorp/boundary/api => ./api

replace github.com/hashicorp/boundary/sdk => ./sdk

//replace github.com/hashicorp/nodeenrollment => ../nodeenrollment

require (
	github.com/armon/go-metrics v0.3.9 // indirect
	github.com/fatih/color v1.13.0
	github.com/fatih/structs v1.1.0
	github.com/favadi/protoc-go-inject-tag v1.3.0
	github.com/godbus/dbus/v5 v5.0.6 // indirect
	github.com/golang-migrate/migrate/v4 v4.15.1
	github.com/golang-sql/civil v0.0.0-20190719163853-cb61b32ac6fe
	github.com/golang/protobuf v1.5.2
	github.com/google/go-cmp v0.5.8
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.11.2
	github.com/hashicorp/boundary/api v0.0.28
	github.com/hashicorp/boundary/sdk v0.0.20
	github.com/hashicorp/cap v0.1.1
	github.com/hashicorp/dawdle v0.4.0
	github.com/hashicorp/dbassert v0.0.0-20210708202608-ecf920cf1ed8
	github.com/hashicorp/eventlogger v0.1.1-0.20211106154408-4ff8da3a890c
	github.com/hashicorp/eventlogger/filters/encrypt v0.1.7
	github.com/hashicorp/go-bexpr v0.1.10
	github.com/hashicorp/go-cleanhttp v0.5.2
	github.com/hashicorp/go-hclog v1.2.2
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.6-0.20220722192355-a843f53fa48d
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hashicorp/go-retryablehttp v0.7.0
	github.com/hashicorp/go-rootcerts v1.0.2
	github.com/hashicorp/go-secure-stdlib/base62 v0.1.2
	github.com/hashicorp/go-secure-stdlib/configutil/v2 v2.0.5
	github.com/hashicorp/go-secure-stdlib/gatedwriter v0.1.1
	github.com/hashicorp/go-secure-stdlib/kv-builder v0.1.1
	github.com/hashicorp/go-secure-stdlib/listenerutil v0.1.4
	github.com/hashicorp/go-secure-stdlib/mlock v0.1.1
	github.com/hashicorp/go-secure-stdlib/parseutil v0.1.7
	github.com/hashicorp/go-secure-stdlib/password v0.1.1
	github.com/hashicorp/go-secure-stdlib/pluginutil/v2 v2.0.2
	github.com/hashicorp/go-secure-stdlib/reloadutil v0.1.1
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2
	github.com/hashicorp/go-sockaddr v1.0.2
	github.com/hashicorp/go-uuid v1.0.3
	github.com/hashicorp/hcl v1.0.0
	github.com/hashicorp/vault/api v1.3.1
	github.com/iancoleman/strcase v0.2.0
	github.com/jackc/pgconn v1.12.1
	github.com/jackc/pgx/v4 v4.16.1
	github.com/jefferai/keyring v1.1.7-0.20220316160357-58a74bb55891
	github.com/kr/pretty v0.3.0
	github.com/kr/text v0.2.0
	github.com/mattn/go-colorable v0.1.12
	github.com/mitchellh/cli v1.1.2
	github.com/mitchellh/copystructure v1.2.0
	github.com/mitchellh/go-wordwrap v1.0.1
	github.com/mitchellh/mapstructure v1.4.2
	github.com/mitchellh/pointerstructure v1.2.0
	github.com/mr-tron/base58 v1.2.0
	github.com/oligot/go-mod-upgrade v0.6.1
	github.com/ory/dockertest/v3 v3.7.0
	github.com/pires/go-proxyproto v0.6.1
	github.com/pkg/errors v0.9.1
	github.com/posener/complete v1.2.3
	github.com/prometheus/client_golang v1.12.1
	github.com/ryanuber/go-glob v1.0.0
	github.com/stretchr/testify v1.8.0
	github.com/zalando/go-keyring v0.2.1
	go.uber.org/atomic v1.9.0
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/sys v0.0.0-20220610221304-9f5ed59c137d
	golang.org/x/term v0.0.0-20210927222741-03fcf44c2211
	golang.org/x/tools v0.1.10
	google.golang.org/genproto v0.0.0-20220805133916-01dd62135a58
	google.golang.org/grpc v1.48.0
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.1.0
	google.golang.org/protobuf v1.28.1
	gorm.io/driver/postgres v1.3.8
	gorm.io/gorm v1.23.8 // indirect
	mvdan.cc/gofumpt v0.3.1
	nhooyr.io/websocket v1.8.7
)

require github.com/hashicorp/go-dbw v0.0.0-20220725170111-b7cb3aa3d628

require (
	github.com/DATA-DOG/go-sqlmock v1.5.0
	github.com/hashicorp/go-kms-wrapping/extras/kms/v2 v2.0.0-20220711120347-32232bae6803
	github.com/hashicorp/nodeenrollment v0.1.13
)

require (
	github.com/99designs/go-keychain v0.0.0-20191008050251-8e49817e8af4 // indirect
	github.com/AlecAivazis/survey/v2 v2.2.9 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20210617225240-d185dfc1b5a1 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.1.1 // indirect
	github.com/Masterminds/sprig v2.22.0+incompatible // indirect
	github.com/Microsoft/go-winio v0.5.0 // indirect
	github.com/Nvveen/Gotty v0.0.0-20120604004816-cd527374f1e5 // indirect
	github.com/alessio/shellescape v1.4.1 // indirect
	github.com/apex/log v1.9.0 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bgentry/speakeasy v0.1.0 // indirect
	github.com/cenkalti/backoff/v3 v3.0.0 // indirect
	github.com/cenkalti/backoff/v4 v4.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/containerd/continuity v0.1.0 // indirect
	github.com/coreos/go-oidc/v3 v3.0.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.0 // indirect
	github.com/danieljoos/wincred v1.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/docker/cli v20.10.7+incompatible // indirect
	github.com/docker/docker v20.10.9+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/docker/go-units v0.4.0 // indirect
	github.com/dvsekhvalnov/jose2go v1.5.0 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/glog v1.0.0 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-kms-wrapping/plugin/v2 v2.0.2 // indirect
	github.com/hashicorp/go-plugin v1.4.3 // indirect
	github.com/hashicorp/go-secure-stdlib/tlsutil v0.1.1 // indirect
	github.com/hashicorp/go-version v1.3.0 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/hashicorp/vault/sdk v0.3.0 // indirect
	github.com/hashicorp/yamux v0.0.0-20181012175058-2f1d1f20f75d // indirect
	github.com/huandu/xstrings v1.3.2 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/pgtype v1.11.0 // indirect
	github.com/jefferai/go-libsecret v0.0.0-20210525195240-b53481abef97 // indirect
	github.com/jefferai/isbadcipher v0.0.0-20190226160619-51d2077c035f // indirect
	github.com/jinzhu/gorm v1.9.12 // indirect
	github.com/jinzhu/inflection v1.0.0 // indirect
	github.com/jinzhu/now v1.1.5 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/klauspost/compress v1.13.6 // indirect
	github.com/lib/pq v1.10.2 // indirect
	github.com/mattn/go-isatty v0.0.14 // indirect
	github.com/mattn/go-sqlite3 v2.0.3+incompatible // indirect
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/mgutz/ansi v0.0.0-20170206155736-9520e82c474b // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-testing-interface v1.0.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/term v0.0.0-20210619224110-3f7ff695adc6 // indirect
	github.com/mtibben/percent v0.2.1 // indirect
	github.com/oklog/run v1.0.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.1 // indirect
	github.com/opencontainers/runc v1.0.2 // indirect
	github.com/pierrec/lz4 v2.5.2+incompatible // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.2.0 // indirect
	github.com/prometheus/common v0.32.1 // indirect
	github.com/prometheus/procfs v0.7.3 // indirect
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	github.com/russross/blackfriday/v2 v2.0.1 // indirect
	github.com/sethvargo/go-diceware v0.3.0 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/sirupsen/logrus v1.8.1 // indirect
	github.com/urfave/cli/v2 v2.3.0 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20180127040702-4e3ac2762d5f // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xo/dburl v0.11.0 // indirect
	go.uber.org/goleak v1.1.10 // indirect
	golang.org/x/mod v0.6.0-dev.0.20220106191415-9b9b3d81d5e3 // indirect
	golang.org/x/net v0.0.0-20220624214902-1bab6f366d9e // indirect
	golang.org/x/oauth2 v0.0.0-20220722155238-128564f6959c // indirect
	golang.org/x/text v0.3.7 // indirect
	golang.org/x/time v0.0.0-20200630173020-3af7569d3a1e // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	gopkg.in/square/go-jose.v2 v2.5.1 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gorm.io/driver/sqlite v1.3.6 // indirect
)
