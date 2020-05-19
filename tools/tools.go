// +build tools

// This file ensures tool dependencies are kept in sync.  This is the
// recommended way of doing this according to
// https://github.com/golang/go/wiki/Modules#how-can-i-track-tool-dependencies-for-a-module
// To install the following tools at the version used by this repo run:
// $ make bootstrap
// or
// $ go generate -tags tools tools/tools.go

package tools

import (
	//go:generate go install github.com/bufbuild/buf/cmd/buf
	_ "github.com/bufbuild/buf/cmd/buf"

	//go:generate go install github.com/favadi/protoc-go-inject-tag
	_ "github.com/favadi/protoc-go-inject-tag"

	//go:generate go install github.com/go-swagger/go-swagger/cmd/swagger
	_ "github.com/go-swagger/go-swagger/cmd/swagger"

	// use this instead of google.golang.org/protobuf/cmd/protoc-gen-go since this supports grpc plugin while the other does not.
	// see https://github.com/golang/protobuf/releases#v1.4-generated-code and
	// https://github.com/protocolbuffers/protobuf-go/releases/tag/v1.20.0#v1.20-grpc-support
	//go:generate go install github.com/golang/protobuf/protoc-gen-go
	_ "github.com/golang/protobuf/protoc-gen-go"

	//go:generate go install github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway"

	//go:generate go install github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger"

	//go:generate go install golang.org/x/tools/cmd/goimports
	_ "golang.org/x/tools/cmd/goimports"
)
