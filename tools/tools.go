// +build tools

// This file ensures tool dependencies are kept in sync.  This is the
// recommended way of doing this according to
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
// To install the following tools at the version used by this repo run:
// $ make tools
// or
// $ go generate -tags tools tools/tools.go

package tools

// NOTE: This must not be indented, so to stop goimports from trying to be
// helpful, it's separated out from the import block below. Please try to keep
// them in the same order.
//go:generate go install github.com/bufbuild/buf/cmd/buf
//go:generate go install github.com/favadi/protoc-go-inject-tag
//go:generate go install github.com/go-swagger/go-swagger/cmd/swagger
//go:generate go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway
//go:generate go install github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2
//go:generate go install golang.org/x/tools/cmd/goimports
//go:generate go install github.com/oligot/go-mod-upgrade
//go:generate go install github.com/mitchellh/gox
//go:generate go install github.com/go-bindata/go-bindata/v3/go-bindata
//go:generate go install google.golang.org/protobuf/cmd/protoc-gen-go
//go:generate go install google.golang.org/grpc/cmd/protoc-gen-go-grpc

import (
	_ "github.com/bufbuild/buf/cmd/buf"

	_ "github.com/favadi/protoc-go-inject-tag"

	_ "github.com/go-swagger/go-swagger/cmd/swagger"

	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-grpc-gateway"

	_ "github.com/grpc-ecosystem/grpc-gateway/v2/protoc-gen-openapiv2"

	_ "golang.org/x/tools/cmd/goimports"

	_ "github.com/oligot/go-mod-upgrade"

	_ "github.com/mitchellh/gox"

	_ "github.com/go-bindata/go-bindata/v3/go-bindata"

	_ "google.golang.org/protobuf/cmd/protoc-gen-go"

	_ "google.golang.org/grpc/cmd/protoc-gen-go-grpc"
)
