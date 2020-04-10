// +build tools

package tools

import (
	_ "github.com/bufbuild/buf/cmd/buf"
	_ "github.com/bufbuild/buf/cmd/protoc-gen-buf-check-breaking"
	_ "github.com/bufbuild/buf/cmd/protoc-gen-buf-check-lint"
	_ "github.com/golang/protobuf/protoc-gen-go"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-grpc-gateway"
	_ "github.com/grpc-ecosystem/grpc-gateway/protoc-gen-swagger"
	_ "github.com/mitchellh/protoc-gen-go-json"
)
