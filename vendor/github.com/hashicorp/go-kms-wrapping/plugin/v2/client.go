// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package plugin

import (
	context "context"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var (
	_ wrapping.Wrapper       = (*wrapClient)(nil)
	_ wrapping.InitFinalizer = (*wrapClient)(nil)
	_ wrapping.HmacComputer  = (*wrapClient)(nil)
	_ wrapping.KeyExporter   = (*wrapClient)(nil)
)

type wrapClient struct {
	impl WrappingClient
}

func (wc *wrapClient) Type(ctx context.Context) (wrapping.WrapperType, error) {
	resp, err := wc.impl.Type(ctx, new(TypeRequest))
	if err != nil {
		return wrapping.WrapperTypeUnknown, err
	}
	return wrapping.WrapperType(resp.Type), nil
}

func (wc *wrapClient) KeyId(ctx context.Context) (string, error) {
	resp, err := wc.impl.KeyId(ctx, new(KeyIdRequest))
	if err != nil {
		return "", err
	}
	return resp.KeyId, nil
}

func (wc *wrapClient) SetConfig(ctx context.Context, options ...wrapping.Option) (*wrapping.WrapperConfig, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.SetConfig(ctx, &SetConfigRequest{
		Options: opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.WrapperConfig, nil
}

func (wc *wrapClient) Encrypt(ctx context.Context, pt []byte, options ...wrapping.Option) (*wrapping.BlobInfo, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.Encrypt(ctx, &EncryptRequest{
		Plaintext: pt,
		Options:   opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.Ciphertext, nil
}

func (wc *wrapClient) Decrypt(ctx context.Context, ct *wrapping.BlobInfo, options ...wrapping.Option) ([]byte, error) {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return nil, err
	}
	resp, err := wc.impl.Decrypt(ctx, &DecryptRequest{
		Ciphertext: ct,
		Options:    opts,
	})
	if err != nil {
		return nil, err
	}
	return resp.Plaintext, nil
}

func (ifc *wrapClient) Init(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = ifc.impl.Init(ctx, &InitRequest{
		Options: opts,
	})
	if status.Code(err) == codes.Unimplemented {
		return wrapping.ErrFunctionNotImplemented
	}
	return err
}

func (ifc *wrapClient) Finalize(ctx context.Context, options ...wrapping.Option) error {
	opts, err := wrapping.GetOpts(options...)
	if err != nil {
		return err
	}
	_, err = ifc.impl.Finalize(ctx, &FinalizeRequest{
		Options: opts,
	})
	if status.Code(err) == codes.Unimplemented {
		return wrapping.ErrFunctionNotImplemented
	}
	return err
}

func (wc *wrapClient) HmacKeyId(ctx context.Context) (string, error) {
	resp, err := wc.impl.HmacKeyId(ctx, new(HmacKeyIdRequest))
	switch {
	case err == nil:
	case status.Code(err) == codes.Unimplemented:
		return "", wrapping.ErrFunctionNotImplemented
	default:
		return "", err
	}
	return resp.KeyId, nil
}

func (wc *wrapClient) KeyBytes(ctx context.Context) ([]byte, error) {
	resp, err := wc.impl.KeyBytes(ctx, new(KeyBytesRequest))
	switch {
	case err == nil:
	case status.Code(err) == codes.Unimplemented:
		return nil, wrapping.ErrFunctionNotImplemented
	default:
		return nil, err
	}
	return resp.KeyBytes, nil
}
