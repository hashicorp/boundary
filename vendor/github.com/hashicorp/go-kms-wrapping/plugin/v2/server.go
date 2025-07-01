// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

type wrapServer struct {
	UnimplementedWrappingServer
	impl wrapping.Wrapper
}

func (ws *wrapServer) Type(ctx context.Context, req *TypeRequest) (*TypeResponse, error) {
	typ, err := ws.impl.Type(ctx)
	if err != nil {
		return nil, err
	}
	return &TypeResponse{Type: typ.String()}, nil
}

func (ws *wrapServer) KeyId(ctx context.Context, req *KeyIdRequest) (*KeyIdResponse, error) {
	keyId, err := ws.impl.KeyId(ctx)
	if err != nil {
		return nil, err
	}
	return &KeyIdResponse{KeyId: keyId}, nil
}

func (ws *wrapServer) SetConfig(ctx context.Context, req *SetConfigRequest) (*SetConfigResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	wc, err := ws.impl.SetConfig(
		ctx,
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}
	return &SetConfigResponse{WrapperConfig: wc}, nil
}

func (ws *wrapServer) Encrypt(ctx context.Context, req *EncryptRequest) (*EncryptResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	ct, err := ws.impl.Encrypt(
		ctx,
		req.Plaintext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}
	return &EncryptResponse{Ciphertext: ct}, nil
}

func (ws *wrapServer) Decrypt(ctx context.Context, req *DecryptRequest) (*DecryptResponse, error) {
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	pt, err := ws.impl.Decrypt(
		ctx,
		req.Ciphertext,
		wrapping.WithAad(opts.WithAad),
		wrapping.WithKeyId(opts.WithKeyId),
		wrapping.WithConfigMap(opts.WithConfigMap),
	)
	if err != nil {
		return nil, err
	}
	return &DecryptResponse{Plaintext: pt}, nil
}

func (ws *wrapServer) Init(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	initFinalizer, ok := ws.impl.(wrapping.InitFinalizer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this wrapper does not implement InitFinalizer")
	}
	opts := req.Options
	if opts == nil {
		opts = new(wrapping.Options)
	}
	if err := initFinalizer.Init(
		ctx,
		wrapping.WithConfigMap(opts.WithConfigMap),
	); err != nil {
		return nil, err
	}
	return &InitResponse{}, nil
}

func (ws *wrapServer) Finalize(ctx context.Context, req *FinalizeRequest) (*FinalizeResponse, error) {
	initFinalizer, ok := ws.impl.(wrapping.InitFinalizer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this wrapper does not implement InitFinalizer")
	}
	if err := initFinalizer.Finalize(
		ctx,
	); err != nil {
		return nil, err
	}
	return &FinalizeResponse{}, nil
}

func (ws *wrapServer) HmacKeyId(ctx context.Context, req *HmacKeyIdRequest) (*HmacKeyIdResponse, error) {
	hmacComputer, ok := ws.impl.(wrapping.HmacComputer)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this wrapper does not implement HmacComputer")
	}
	hmacKeyId, err := hmacComputer.HmacKeyId(ctx)
	if err != nil {
		return nil, err
	}
	return &HmacKeyIdResponse{KeyId: hmacKeyId}, nil
}

func (ws *wrapServer) KeyBytes(ctx context.Context, req *KeyBytesRequest) (*KeyBytesResponse, error) {
	keyExporter, ok := ws.impl.(wrapping.KeyExporter)
	if !ok {
		return nil, status.Error(codes.Unimplemented, "this wrapper does not implement HmacComputer")
	}
	keyBytes, err := keyExporter.KeyBytes(ctx)
	if err != nil {
		return nil, err
	}
	return &KeyBytesResponse{KeyBytes: keyBytes}, nil
}
