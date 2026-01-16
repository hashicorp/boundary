// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package handlers

import (
	"context"

	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ParseListToken parses a list token from the input, returning
// an error if the parsing fails.
func ParseListToken(
	ctx context.Context,
	token string,
	expectedResourceType resource.Type,
	expectedGrantsHash []byte,
) (*listtoken.Token, error) {
	const op = "handlers.ParseListToken"
	marshaled, err := base58.Decode(token)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var tok pbs.ListToken
	if err := proto.Unmarshal(marshaled, &tok); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var listToken *listtoken.Token
	switch st := tok.Token.(type) {
	case *pbs.ListToken_PaginationToken:
		listToken, err = listtoken.NewPagination(
			ctx,
			tok.CreateTime.AsTime(),
			ListTokenResourceToResource(tok.ResourceType),
			tok.GrantsHash,
			st.PaginationToken.LastItemId,
			st.PaginationToken.LastItemCreateTime.AsTime(),
		)
		if err != nil {
			return nil, err
		}
	case *pbs.ListToken_StartRefreshToken:
		listToken, err = listtoken.NewStartRefresh(
			ctx,
			tok.CreateTime.AsTime(),
			ListTokenResourceToResource(tok.ResourceType),
			tok.GrantsHash,
			st.StartRefreshToken.PreviousDeletedIdsTime.AsTime(),
			st.StartRefreshToken.PreviousPhaseUpperBound.AsTime(),
		)
		if err != nil {
			return nil, err
		}
	case *pbs.ListToken_RefreshToken:
		listToken, err = listtoken.NewRefresh(
			ctx,
			tok.CreateTime.AsTime(),
			ListTokenResourceToResource(tok.ResourceType),
			tok.GrantsHash,
			st.RefreshToken.PreviousDeletedIdsTime.AsTime(),
			st.RefreshToken.PhaseUpperBound.AsTime(),
			st.RefreshToken.PhaseLowerBound.AsTime(),
			st.RefreshToken.LastItemId,
			st.RefreshToken.LastItemUpdateTime.AsTime(),
		)
		if err != nil {
			return nil, err
		}
	default:
		return nil, ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
	}
	if err := listToken.Validate(ctx, expectedResourceType, expectedGrantsHash); err != nil {
		return nil, err
	}
	return listToken, nil
}

// MarshalListToken assembles and marshals a list token to its string representation.
func MarshalListToken(ctx context.Context, token *listtoken.Token, resourceType pbs.ResourceType) (string, error) {
	const op = "handlers.MarshalListToken"
	switch {
	case token == nil:
		return "", errors.New(ctx, errors.InvalidParameter, op, "token is required")
	case resourceType == pbs.ResourceType_RESOURCE_TYPE_UNSPECIFIED:
		return "", errors.New(ctx, errors.InvalidParameter, op, "missing resource type")
	case token.ResourceType != ListTokenResourceToResource(resourceType):
		return "", errors.New(ctx, errors.Internal, op, "list token resource type does not match expected resource type")
	}
	lt := &pbs.ListToken{
		CreateTime:   timestamppb.New(token.CreateTime),
		ResourceType: resourceType,
		GrantsHash:   token.GrantsHash,
	}
	switch st := token.Subtype.(type) {
	case *listtoken.PaginationToken:
		lt.Token = &pbs.ListToken_PaginationToken{
			PaginationToken: &pbs.PaginationToken{
				LastItemId:         st.LastItemId,
				LastItemCreateTime: timestamppb.New(st.LastItemCreateTime),
			},
		}
	case *listtoken.StartRefreshToken:
		lt.Token = &pbs.ListToken_StartRefreshToken{
			StartRefreshToken: &pbs.StartRefreshToken{
				PreviousPhaseUpperBound: timestamppb.New(st.PreviousPhaseUpperBound),
				PreviousDeletedIdsTime:  timestamppb.New(st.PreviousDeletedIdsTime),
			},
		}
	case *listtoken.RefreshToken:
		lt.Token = &pbs.ListToken_RefreshToken{
			RefreshToken: &pbs.RefreshToken{
				PhaseUpperBound:        timestamppb.New(st.PhaseUpperBound),
				PhaseLowerBound:        timestamppb.New(st.PhaseLowerBound),
				PreviousDeletedIdsTime: timestamppb.New(st.PreviousDeletedIdsTime),
				LastItemId:             st.LastItemId,
				LastItemUpdateTime:     timestamppb.New(st.LastItemUpdateTime),
			},
		}
	default:
		return "", errors.New(ctx, errors.Internal, op, "unexpected list token subtype")
	}
	marshaled, err := proto.Marshal(lt)
	if err != nil {
		return "", errors.Wrap(ctx, err, op)
	}
	return base58.Encode(marshaled), nil
}

// ListTokenResourceToResource translates a protobuf list token resource type
// into a useable domain layer boundary resource type.
func ListTokenResourceToResource(rt pbs.ResourceType) resource.Type {
	switch rt {
	case pbs.ResourceType_RESOURCE_TYPE_ACCOUNT:
		return resource.Account
	case pbs.ResourceType_RESOURCE_TYPE_ALIAS:
		return resource.Alias
	case pbs.ResourceType_RESOURCE_TYPE_AUTH_METHOD:
		return resource.AuthMethod
	case pbs.ResourceType_RESOURCE_TYPE_AUTH_TOKEN:
		return resource.AuthToken
	case pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL_LIBRARY:
		return resource.CredentialLibrary
	case pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL_STORE:
		return resource.CredentialStore
	case pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL:
		return resource.Credential
	case pbs.ResourceType_RESOURCE_TYPE_GROUP:
		return resource.Group
	case pbs.ResourceType_RESOURCE_TYPE_HOST_CATALOG:
		return resource.HostCatalog
	case pbs.ResourceType_RESOURCE_TYPE_HOST_SET:
		return resource.HostSet
	case pbs.ResourceType_RESOURCE_TYPE_HOST:
		return resource.Host
	case pbs.ResourceType_RESOURCE_TYPE_MANAGED_GROUP:
		return resource.ManagedGroup
	case pbs.ResourceType_RESOURCE_TYPE_ROLE:
		return resource.Role
	case pbs.ResourceType_RESOURCE_TYPE_SCOPE:
		return resource.Scope
	case pbs.ResourceType_RESOURCE_TYPE_SESSION_RECORDING:
		return resource.SessionRecording
	case pbs.ResourceType_RESOURCE_TYPE_SESSION:
		return resource.Session
	case pbs.ResourceType_RESOURCE_TYPE_STORAGE_BUCKET:
		return resource.StorageBucket
	case pbs.ResourceType_RESOURCE_TYPE_TARGET:
		return resource.Target
	case pbs.ResourceType_RESOURCE_TYPE_USER:
		return resource.User
	case pbs.ResourceType_RESOURCE_TYPE_WORKER:
		return resource.Worker
	case pbs.ResourceType_RESOURCE_TYPE_POLICY:
		return resource.Policy
	default:
		return resource.Unknown
	}
}
