// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package types

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/nodeenrollment"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Store stores an activation token to storage, wrapping values along the way if
// given a wrapper
//
// Supported options: WithStorageWrapper
func (s *ServerLedActivationToken) Store(ctx context.Context, storage nodeenrollment.Storage, opt ...nodeenrollment.Option) error {
	const op = "nodeenrollment.types.(ServerLedActivationToken).Store"

	switch {
	case nodeenrollment.IsNil(storage):
		return fmt.Errorf("(%s) storage is nil", op)

	case nodeenrollment.IsNil(s):
		return fmt.Errorf("(%s) server-led activation token is nil", op)

	case nodeenrollment.IsNil(s.CreationTime):
		return fmt.Errorf("(%s) creation time is nil", op)

	case s.CreationTime.AsTime().IsZero():
		return fmt.Errorf("(%s) creation time is zero", op)

	case s.Id == "":
		return fmt.Errorf("(%s) missing id", op)
	}

	var err error
	s.CreationTimeMarshaled, err = proto.Marshal(s.CreationTime)
	if err != nil {
		return fmt.Errorf("(%s) error marshaling creation time: %w", op, err)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	tokenToStore := s
	if opts.WithStorageWrapper != nil {
		tokenToStore = proto.Clone(s).(*ServerLedActivationToken)

		keyId, err := opts.WithStorageWrapper.KeyId(ctx)
		if err != nil {
			return fmt.Errorf("(%s) error reading wrapper key id: %w", op, err)
		}
		tokenToStore.WrappingKeyId = keyId

		blobInfo, err := opts.WithStorageWrapper.Encrypt(
			ctx,
			tokenToStore.CreationTimeMarshaled,
			wrapping.WithAad([]byte(tokenToStore.Id)),
		)
		if err != nil {
			return fmt.Errorf("(%s) error wrapping creation time %w", op, err)
		}
		tokenToStore.CreationTimeMarshaled, err = proto.Marshal(blobInfo)
		if err != nil {
			return fmt.Errorf("(%s) error marshaling wrapped creation time: %w", op, err)
		}
	}

	if err := storage.Store(ctx, tokenToStore); err != nil {
		return fmt.Errorf("(%s) error storing server-led activation token: %w", op, err)
	}

	return nil
}

// LoadServerLedActivationToken loads the node credentials from storage, unwrapping
// encrypted values if needed
//
// Supported options: WithStorageWrapper
func LoadServerLedActivationToken(ctx context.Context, storage nodeenrollment.Storage, id string, opt ...nodeenrollment.Option) (*ServerLedActivationToken, error) {
	const op = "nodeenrollment.types.LoadServerLedActivationToken"

	if nodeenrollment.IsNil(storage) {
		return nil, fmt.Errorf("(%s) storage is nil", op)
	}

	switch {
	case nodeenrollment.IsNil(storage):
		return nil, fmt.Errorf("(%s) storage is nil", op)
	case id == "":
		return nil, fmt.Errorf("(%s) missing id", op)
	}

	opts, err := nodeenrollment.GetOpts(opt...)
	if err != nil {
		return nil, fmt.Errorf("(%s) error parsing options: %w", op, err)
	}

	token := &ServerLedActivationToken{
		Id: string(id),
	}
	if err := storage.Load(ctx, token); err != nil {
		return nil, fmt.Errorf("(%s) error loading server-led activation token from storage: %w", op, err)
	}

	switch {
	case opts.WithStorageWrapper == nil && token.WrappingKeyId != "":
		return nil, fmt.Errorf("(%s) server-led activation token has encrypted parts with wrapper key id %q but wrapper not provided", op, token.WrappingKeyId)
	case token.WrappingKeyId != "":
		// Note: not checking the wrapper key IDs against each other because if
		// using something like a PooledWrapper then the current encryping ID
		// may not match, or if the wrapper performs its own internal key
		// selection.
		blobInfo := new(wrapping.BlobInfo)
		if err := proto.Unmarshal(token.CreationTimeMarshaled, blobInfo); err != nil {
			return nil, fmt.Errorf("(%s) error unmarshaling creation time blob info: %w", op, err)
		}
		pt, err := opts.WithStorageWrapper.Decrypt(
			ctx,
			blobInfo,
			wrapping.WithAad([]byte(id)),
		)
		if err != nil {
			return nil, fmt.Errorf("(%s) error decrypting creation time: %w", op, err)
		}
		token.CreationTimeMarshaled = pt

		token.WrappingKeyId = ""
	}

	token.CreationTime = new(timestamppb.Timestamp)
	if err := proto.Unmarshal(token.CreationTimeMarshaled, token.CreationTime); err != nil {
		return nil, fmt.Errorf("(%s) error unmarshaling creation time: %w", op, err)
	}

	return token, nil
}
