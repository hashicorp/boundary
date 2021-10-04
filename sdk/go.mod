module github.com/hashicorp/boundary/sdk

go 1.16

replace github.com/hashicorp/boundary/plugins => ../plugins

require (
	github.com/fatih/color v1.12.0 // indirect
	github.com/google/go-cmp v0.5.6 // indirect
	github.com/hashicorp/boundary/plugins v0.0.0-20210826145033-423a0b14037e
	github.com/hashicorp/eventlogger v0.1.0
	github.com/hashicorp/eventlogger/filters/encrypt v0.1.3
	github.com/hashicorp/go-hclog v0.16.2
	github.com/hashicorp/go-kms-wrapping v0.6.6 // indirect
	github.com/hashicorp/go-kms-wrapping/v2 v2.0.0-20211004181108-59533a548d29
	github.com/hashicorp/go-kms-wrapping/wrappers/aead/v2 v2.0.0-20211004181156-d323e1064fea
	github.com/hashicorp/go-secure-stdlib/configutil/v2 v2.0.0-20211004181859-a8520a696314
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.1
	github.com/jhump/protoreflect v1.8.1 // indirect
	github.com/kr/pretty v0.2.1 // indirect
	github.com/mattn/go-isatty v0.0.13 // indirect
	github.com/posener/complete v1.2.3 // indirect
	github.com/stretchr/testify v1.7.0
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97 // indirect
	golang.org/x/net v0.0.0-20210510120150-4163338589ed // indirect
	golang.org/x/sys v0.0.0-20210630005230-0f9fa26af87c // indirect
	golang.org/x/tools v0.1.3 // indirect
	google.golang.org/genproto v0.0.0-20210319143718-93e7006c17a6 // indirect
	google.golang.org/protobuf v1.27.1
	gopkg.in/yaml.v2 v2.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b // indirect
)
