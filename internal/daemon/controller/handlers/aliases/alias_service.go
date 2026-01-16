// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package aliases

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/alias/target"
	"github.com/hashicorp/boundary/internal/alias/target/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/aliases"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)
)

const aliasTypeTarget = "target"

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.Alias{}},
		handlers.MaskSource{&pb.Alias{}, &pb.AuthorizeSessionArguments{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove IdActionsMap and CollectionActions package variables
	action.RegisterResource(resource.Alias, action.Union(IdActions), CollectionActions)
}

// Service handles requests as described by the pbs.AliasServiceServer interface.
type Service struct {
	pbs.UnsafeAliasServiceServer

	repoFn      common.TargetAliasRepoFactory
	iamRepoFn   common.IamRepoFactory
	maxPageSize uint
}

var _ pbs.AliasServiceServer = (*Service)(nil)

// NewService returns a alias service which handles alias related requests to boundary.
func NewService(ctx context.Context, repo common.TargetAliasRepoFactory, iamRepo common.IamRepoFactory, maxPageSize uint) (Service, error) {
	const op = "aliasess.NewService"
	if iamRepo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing alias repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{repoFn: repo, iamRepoFn: iamRepo, maxPageSize: maxPageSize}, nil
}

// ListAliases implements the interface pbs.AliasServiceServer.
func (s Service) ListAliases(ctx context.Context, req *pbs.ListAliasesRequest) (*pbs.ListAliasesResponse, error) {
	const op = "aliases.(Service).ListAliases"
	if err := validateListRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List, req.GetRecursive())
	if authResults.Error != nil {
		// If it's forbidden, and it's a recursive request, and they're
		// successfully authenticated but just not authorized, keep going as we
		// may have authorization on downstream scopes. Or, if they've not
		// authenticated, still process in case u_anon has permissions.
		if (authResults.Error == handlers.ForbiddenError() || authResults.Error == handlers.UnauthenticatedError()) &&
			req.GetRecursive() &&
			authResults.AuthenticationFinished {
		} else {
			return nil, authResults.Error
		}
	}

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.Alias, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListAliasesResponse{}, nil
	}

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item *target.Alias) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		filterItemFn = func(ctx context.Context, item *target.Alias) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, outputOpts...)
			if err != nil {
				return false, err
			}
			return filter.Match(pbItem), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item *target.Alias) (bool, error) {
			return true, nil
		}
	}

	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var listResp *pagination.ListResponse[*target.Alias]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = target.ListAliases(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Alias, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = target.ListAliasesPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = target.ListAliasesRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = target.ListAliasesRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.Alias, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, scopeInfoMap, authResults)
		if !ok {
			continue
		}
		item, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, item)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListAliasesResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}
	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_ALIAS)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// GetAlias implements the interface pbs.AliasServiceServer.
func (s Service) GetAlias(ctx context.Context, req *pbs.GetAliasRequest) (*pbs.GetAliasResponse, error) {
	const op = "aliases.(Service).GetAlias"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetAliasResponse{Item: item}, nil
}

// CreateAlias implements the interface pbs.AliasServiceServer.
func (s Service) CreateAlias(ctx context.Context, req *pbs.CreateAliasRequest) (*pbs.CreateAliasResponse, error) {
	const op = "aliases.(Service).CreateAlias"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	a, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, a.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, a, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateAliasResponse{Item: item, Uri: fmt.Sprintf("aliases/%s", item.GetId())}, nil
}

// UpdateAlias implements the interface pbs.AliasServiceServer.
func (s Service) UpdateAlias(ctx context.Context, req *pbs.UpdateAliasRequest) (*pbs.UpdateAliasResponse, error) {
	const op = "aliases.(Service).UpdateAlias"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, u.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, u, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateAliasResponse{Item: item}, nil
}

// DeleteAlias implements the interface pbs.AliasServiceServer.
func (s Service) DeleteAlias(ctx context.Context, req *pbs.DeleteAliasRequest) (*pbs.DeleteAliasResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*target.Alias, error) {
	const op = "aliases.(Service).getFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	g, err := repo.LookupAlias(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, errors.Wrap(ctx, err, op)
	}
	if g == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("alias %q not found", id))
	}
	return g, err
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Alias) (*target.Alias, error) {
	const op = "aliases.(Service).createInRepo"
	var opts []target.Option
	if item.GetDescription() != nil {
		opts = append(opts, target.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetName() != nil {
		opts = append(opts, target.WithName(item.GetName().GetValue()))
	}
	if item.GetDestinationId() != nil {
		opts = append(opts, target.WithDestinationId(item.GetDestinationId().GetValue()))
	}
	if item.GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId() != "" {
		opts = append(opts, target.WithHostId(item.GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId()))
	}
	a, err := target.NewAlias(ctx, scopeId, item.GetValue(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build alias for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, err := repo.CreateAlias(ctx, a)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create alias but no error returned from repository.")
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Alias) (*target.Alias, error) {
	const op = "aliases.(Service).updateInRepo"
	var opts []target.Option
	if item.GetDescription() != nil {
		opts = append(opts, target.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetName() != nil {
		opts = append(opts, target.WithName(item.GetName().GetValue()))
	}
	if item.GetDestinationId() != nil {
		opts = append(opts, target.WithDestinationId(item.GetDestinationId().GetValue()))
	}
	if item.GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId() != "" {
		opts = append(opts, target.WithHostId(item.GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId()))
	}
	version := item.GetVersion()
	g, err := target.NewAlias(ctx, scopeId, item.GetValue(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build alias for update: %v.", err)
	}
	g.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateAlias(ctx, g, version, dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Alias %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "aliases.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteAlias(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete alias"))
	}
	return rows > 0, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type, isRecursive bool) auth.VerifyResults {
	res := auth.VerifyResults{}
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive)}
	switch a {
	case action.List, action.Create:
		parentId = id
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
		grp, err := repo.LookupAlias(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if grp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = grp.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, resource.Alias, opts...)
}

func toProto(ctx context.Context, in *target.Alias, opt ...handlers.Option) (*pb.Alias, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building alias proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Alias{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = aliasTypeTarget
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if outputFields.Has(globals.ValueField) && in.GetValue() != "" {
		out.Value = in.GetValue()
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
	}
	if outputFields.Has(globals.UpdatedTimeField) {
		out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
	}
	if outputFields.Has(globals.VersionField) {
		out.Version = in.GetVersion()
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.DestinationIdField) && in.GetDestinationId() != "" {
		out.DestinationId = wrapperspb.String(in.GetDestinationId())
	}
	if outputFields.Has(globals.AttributesField) && in.GetHostId() != "" {
		out.Attrs = &pb.Alias_TargetAliasAttributes{
			TargetAliasAttributes: &pb.TargetAliasAttributes{
				AuthorizeSessionArguments: &pb.AuthorizeSessionArguments{
					HostId: in.GetHostId(),
				},
			},
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAliasRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.TargetAliasPrefix)
}

func validateCreateRequest(req *pbs.CreateAliasRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if scope.Global.String() != req.GetItem().GetScopeId() {
			badFields["scope_id"] = "This field is missing or improperly formatted."
		}
		if req.GetItem().GetValue() == "" {
			badFields[globals.ValueField] = "This field is required."
		}
		if !strings.EqualFold(req.GetItem().GetType(), aliasTypeTarget) {
			badFields[globals.TypeField] = "This field is required. Current supported values are 'target'."
		}
		if req.GetItem().GetDestinationId().GetValue() != "" &&
			!handlers.ValidId(handlers.Id(req.GetItem().GetDestinationId().GetValue()), globals.TcpTargetPrefix, globals.SshTargetPrefix, globals.RdpTargetPrefix) {
			badFields[globals.DestinationIdField] = "Incorrectly formatted identifier."
		}
		if req.GetItem().GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId() != "" {
			if req.GetItem().GetDestinationId().GetValue() == "" {
				badFields[globals.DestinationIdField] = "This field is required when 'attributes.authorize_session_arguments.host_id' is specified."
			}
			if !handlers.ValidId(handlers.Id(req.GetItem().GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId()), globals.StaticHostPrefix, globals.PluginHostPrefix) {
				badFields["attributes.authorize_session_arguments.host_id"] = "Incorrectly formatted identifier."
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateAliasRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), "value") && req.GetItem().GetValue() == "" {
			badFields["value"] = "This field is required."
		}
		if req.GetItem().GetDestinationId().GetValue() != "" &&
			!handlers.ValidId(handlers.Id(req.GetItem().GetDestinationId().GetValue()), globals.TcpTargetPrefix, globals.SshTargetPrefix, globals.RdpTargetPrefix) {
			badFields[globals.DestinationIdField] = "Incorrectly formatted identifier."
		}
		if req.GetItem().GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId() != "" &&
			!handlers.ValidId(handlers.Id(req.GetItem().GetTargetAliasAttributes().GetAuthorizeSessionArguments().GetHostId()), globals.StaticHostPrefix, globals.PluginHostPrefix) {
			badFields["attributes.authorize_session_arguments.host_id"] = "Incorrectly formatted identifier."
		}
		return badFields
	}, globals.TargetAliasPrefix)
}

func validateDeleteRequest(req *pbs.DeleteAliasRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.TargetAliasPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListAliasesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) &&
		!handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Incorrectly formatted identifier."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func newOutputOpts(ctx context.Context, item *target.Alias, scopeInfoMap map[string]*scopes.ScopeInfo, authResults auth.VerifyResults) ([]handlers.Option, bool) {
	res := perms.Resource{
		Type: resource.Alias,
	}
	res.Id = item.GetPublicId()
	res.ScopeId = item.GetScopeId()
	res.ParentScopeId = scopeInfoMap[item.GetScopeId()].GetParentScopeId()
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res))
	if len(authorizedActions) == 0 {
		return nil, false
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetScopeId()]))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions.Strings()))
	}
	return outputOpts, true
}
