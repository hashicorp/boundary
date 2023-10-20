// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

// ParseRefreshToken parses a refresh token from the input, returning
// an error if the parsing fails.
func ParseRefreshToken(ctx context.Context, token string) (*pbs.ListRefreshToken, error) {
	const op = "handlers.ParseRefreshToken"
	marshaled, err := base58.Decode(token)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidRefreshToken))
	}
	var tok pbs.ListRefreshToken
	if err := proto.Unmarshal(marshaled, &tok); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.InvalidRefreshToken))
	}
	return &tok, nil
}

// MarshalRefreshToken marshals a refresh token to its string representation.
func MarshalRefreshToken(ctx context.Context, token *pbs.ListRefreshToken) (string, error) {
	const op = "handlers.MarshalRefreshToken"
	if token == nil {
		return "", errors.New(ctx, errors.InvalidParameter, op, "token is required")
	}
	marshaled, err := proto.Marshal(token)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return base58.Encode(marshaled), nil
}

// RefreshTokenResourceToResource translates a protobuf refresh token resource type
// into a useable domain layer boundary resource type.
func RefreshTokenResourceToResource(rt pbs.ResourceType) resource.Type {
	switch rt {
	case pbs.ResourceType_RESOURCE_TYPE_TARGET:
		return resource.Target
	case pbs.ResourceType_RESOURCE_TYPE_SESSION:
		return resource.Session
	case pbs.ResourceType_RESOURCE_TYPE_HOST,
		pbs.ResourceType_RESOURCE_TYPE_SESSION_RECORDING,
		pbs.ResourceType_RESOURCE_TYPE_AUTH_TOKEN,
		pbs.ResourceType_RESOURCE_TYPE_ACCOUNT,
		pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL_LIBRARY,
		pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL_STORE:
		return resource.Unknown
	default:
		return resource.Unknown
	}
}
