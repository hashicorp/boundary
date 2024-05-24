// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package apptokens

import (
	"context"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/apptoken"
	"github.com/hashicorp/boundary/internal/apptoken/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/apptokens"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/apptokens"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Delete,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

type Service struct {
	repoFn    apptoken.RepositoryFactory
	iamRepoFn common.IamRepoFactory
}

func NewService(ctx context.Context, repoFn apptoken.RepositoryFactory, iamRepoFn common.IamRepoFactory) (*Service, error) {
	const op = "apptokens.NewService"

	if repoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing apptoken repository")
	}
	if iamRepoFn == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}

	return &Service{
		repoFn:    repoFn,
		iamRepoFn: iamRepoFn,
	}, nil
}

func (s *Service) CreateAppToken(ctx context.Context, req *pbs.CreateAppTokenRequest) (*pbs.CreateAppTokenResponse, error) {
	const op = "apptokens.(Service).CreateAppToken"

	if err := validateCreateRequest(ctx, req); err != nil {
		return nil, err
	}

	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create, "")
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	appToken, err := s.createInRepo(ctx, req.Item)
	if err != nil {
		return nil, err
	}

	pbsAppToken, err := toProto(ctx, *appToken, handlers.WithScope(authResults.Scope))

	return &pbs.CreateAppTokenResponse{
		Item: pbsAppToken,
	}, nil
}

func (s Service) createInRepo(ctx context.Context, item *pb.AppToken) (*apptoken.AppToken, error) {
	const op = "apptokens.(Service).createInRepo"
	opts := []apptoken.Option{}
	if item.GetDescription() != nil {
		opts = append(opts, apptoken.WithDescription(ctx, item.GetDescription().GetValue()))
	}
	if item.GetName() != nil {
		opts = append(opts, apptoken.WithName(ctx, item.GetDescription().GetValue()))
	}
	if item.GetGrantScopeId() != nil {
		opts = append(opts, apptoken.WithGrantScopeId(ctx, item.GetGrantScopeId().GetValue()))
	}

	repo, err := s.repoFn()
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "internal error")
	}
	out, err := repo.CreateAppToken(ctx,
		item.GetScopeId(),
		item.GetExpirationTime().AsTime(),
		item.GetCreatedByUserId(),
		item.GetGrantStrings(),
		opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "unable to create apptoken")
	}

	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "unable to create apptoken but no error returned from repository.")
	}
	return out, nil
}

func validateCreateRequest(ctx context.Context, req *pbs.CreateAppTokenRequest) error {
	const op = "apptokens.validateCreateRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	badFields := map[string]string{}

	now := time.Now()

	i := req.GetItem()
	if i == nil {
		badFields["item"] = "This field is required."
	}
	if i.GetId() != "" {
		badFields["id"] = "This is a read only field."
	}
	if i.GetName() != nil {
		trimmed := strings.TrimSpace(i.GetName().GetValue())
		switch {
		case trimmed == "":
			badFields["name"] = "Cannot set empty string as name"
		case !handlers.ValidNameDescription(trimmed):
			badFields["name"] = "Name contains unprintable characters"
		default:
			i.GetName().Value = trimmed
		}
	}
	if i.GetDescription() != nil {
		trimmed := strings.TrimSpace(i.GetDescription().GetValue())
		switch {
		case trimmed == "":
			badFields["description"] = "Cannot set empty string as description"
		case !handlers.ValidNameDescription(trimmed):
			badFields["description"] = "Description contains unprintable characters"
		default:
			i.GetDescription().Value = trimmed
		}
	}
	if i.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field."
	}
	if i.GetScopeId() == "" {
		badFields["item.scope"] = "This field is required."
	}
	if i.GetGrantStrings() == nil && len(req.GetItem().GetGrantStrings()) == 0 {
		badFields["item.grants"] = "This field is required."
	}
	if i.GetExpirationTime() == nil {
		badFields["item.expiration_time"] = "This field is required."
	}
	if i.GetExpirationTime() != nil {
		exp := i.GetExpirationTime().AsTime()
		switch {
		case exp.IsZero():
			badFields["expiration_time"] = "Expiration time cannot be zero."
		case exp.Before(now):
			badFields["expiration_time"] = "Expiration time cannot be in the past."
		case exp.After(now.Add(time.Hour * 24 * 365 * 3)):
			badFields["expiration_time"] = "Expiration time cannot be more than 3 years in the future."
		case i.ExpirationInterval != 0:
			// The validation for the expiration time must be done before this check
			timeToExpire := i.GetExpirationTime().AsTime().Sub(now).Round(time.Second)
			if i.ExpirationInterval > uint32(timeToExpire) {
				badFields["expiration_interval"] = "Expiration interval cannot be greater than the time to expire."
			}
		}
	}

	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func (s Service) authResult(ctx context.Context, scopeID string, a action.Type, appTokenID string) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	var at *apptoken.AppToken
	opts := []auth.Option{auth.WithType(resource.Target), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = scopeID
		iamRepo, err := s.iamRepoFn()
		if err != nil {
			res.Error = err
			return res
		}
		scp, err := iamRepo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if scp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	default:
		repo, err := s.repoFn()
		if err != nil {
			res.Error = err
			return res
		}
		at, err = repo.LookupAppToken(ctx, appTokenID)
		if err != nil {
			res.Error = err
			return res
		}
		if at == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		scopeID = at.GetScopeId()
		opts = append(opts, auth.WithId(scopeID))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	ret := auth.Verify(ctx, opts...)
	return ret
}

func toProto(ctx context.Context, in apptoken.AppToken, opt ...handlers.Option) (*apptokens.AppToken, error) {
	const op = "apptoken_service.toProto"
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building apptoken proto")
	}
	outputFields := *opts.WithOutputFields

	out := apptokens.AppToken{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
	}
	if outputFields.Has(globals.NameField) {
		out.Name = wrapperspb.String(in.GetName())
	}
	if outputFields.Has(globals.DescriptionField) {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
	}
	if outputFields.Has(globals.ExpirationTimeField) {
		out.ExpirationTime = in.GetExpirationTime().GetTimestamp()
	}
	if outputFields.Has(globals.CreatedByField) {
		out.CreatedByUserId = in.GetCreatedBy()
	}
	if outputFields.Has(globals.ExpirationIntervalField) {
		out.ExpirationInterval = in.GetExpirationIntervalInMaxSeconds()
	}
	if outputFields.Has(globals.GrantStringsField) {
		for _, g := range in.GetGrants() {
			out.GrantStrings = append(out.GrantStrings, g.GetRawGrant())
		}
	}
	if outputFields.Has(globals.GrantsField) {
		grantspb, err := grantToProto(ctx, in.GetGrants(), in.GetScopeId(), opt...)
		if err != nil {
			return nil, err
		}
		out.Grants = grantspb
	}
	if outputFields.Has(globals.GrantScopeIdField) {
		out.GrantScopeId = wrapperspb.String(in.GetGrantScopeId())
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}

	return &out, nil
}

func grantToProto(ctx context.Context, in []*store.AppTokenGrant, scopeId string, opt ...handlers.Option) ([]*apptokens.Grant, error) {
	const op = "apptoken_service.grantToProto"

	switch {
	case in == nil:
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "empty grants slice when building apptoken_grant proto")
	case scopeId == "":
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "scope id is empty when building apptoken_grant proto")
	}

	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building apptoken_grant proto")
	}
	outputFields := *opts.WithOutputFields

	out := []*apptokens.Grant{}
	for _, g := range in {
		if g == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "nil grant when building apptoken_grant proto")
		}
		grantPb := &apptokens.Grant{}
		if outputFields.Has(globals.CanonicalGrantField) {
			grantPb.Canonical = g.GetCanonicalGrant()
		}
		if outputFields.Has(globals.JsonGrantField) {
			parsed, err := perms.Parse(ctx, scopeId, g.GetRawGrant())
			if err != nil {
				// This should never happen as we validate on the way in, but let's
				// return what we can since we are still returning the raw grant
				grantPb = &pb.Grant{
					Raw:       g.GetRawGrant(),
					Canonical: "<parse_error>",
					Json:      nil,
				}
			} else {
				_, actions := parsed.Actions()
				grantPb = &pb.Grant{
					Raw:       g.GetRawGrant(),
					Canonical: g.GetCanonicalGrant(),
					Json: &pb.GrantJson{
						Ids:     parsed.Ids(),
						Type:    parsed.Type().String(),
						Actions: actions,
					},
				}
			}
		}
		if outputFields.Has(globals.RawGrantField) {
			grantPb.Raw = g.GetRawGrant()
		}
		out = append(out, grantPb)
	}
	return out, nil
}
