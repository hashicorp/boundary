// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package scopes

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/aliases"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/apptokens"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authmethods"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/authtokens"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentialstores"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/host_catalogs"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/policies"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/roles"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/session_recordings"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/storage_buckets"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/targets"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/users"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/workers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	wrappingKms "github.com/hashicorp/go-kms-wrapping/extras/kms/v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
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
		action.AttachStoragePolicy,
		action.DetachStoragePolicy,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
		action.ListScopeKeys,
		action.RotateScopeKeys,
		action.ListScopeKeyVersionDestructionJobs,
		action.DestroyScopeKeyVersion,
	)

	// TODO: get this from action registry
	scopeCollectionTypeMapMap = map[string]map[resource.Type]action.ActionSet{
		scope.Global.String(): {
			resource.Alias:            aliases.CollectionActions,
			resource.AuthMethod:       authmethods.CollectionActions,
			resource.StorageBucket:    storage_buckets.CollectionActions,
			resource.AuthToken:        authtokens.CollectionActions,
			resource.AppToken:         apptokens.CollectionActions,
			resource.Group:            groups.CollectionActions,
			resource.Role:             roles.CollectionActions,
			resource.Scope:            CollectionActions,
			resource.User:             users.CollectionActions,
			resource.Worker:           workers.CollectionActions,
			resource.SessionRecording: session_recordings.CollectionActions,
			resource.Policy:           policies.CollectionActions,
		},

		scope.Org.String(): {
			resource.AuthMethod:       authmethods.CollectionActions,
			resource.StorageBucket:    storage_buckets.CollectionActions,
			resource.AuthToken:        authtokens.CollectionActions,
			resource.AppToken:         apptokens.CollectionActions,
			resource.Group:            groups.CollectionActions,
			resource.Role:             roles.CollectionActions,
			resource.Scope:            CollectionActions,
			resource.User:             users.CollectionActions,
			resource.SessionRecording: session_recordings.CollectionActions,
			resource.Policy:           policies.CollectionActions,
		},

		scope.Project.String(): {
			resource.CredentialStore: credentialstores.CollectionActions,
			resource.Group:           groups.CollectionActions,
			resource.HostCatalog:     host_catalogs.CollectionActions,
			resource.Role:            roles.CollectionActions,
			resource.Scope: action.NewActionSet(
				action.ListScopeKeys,
				action.RotateScopeKeys,
				action.ListScopeKeyVersionDestructionJobs,
				action.DestroyScopeKeyVersion,
			), // Only Scope key actions are allowed on the project level
			resource.Session: sessions.CollectionActions,
			resource.Target:  targets.CollectionActions,
		},
	}
	additionalResourceGrants = []resource.Type{
		resource.Alias,
		resource.AuthMethod,
		resource.AuthToken,
		resource.AppToken,
		resource.StorageBucket,
		resource.Group,
		resource.Role,
		resource.Scope,
		resource.User,
		resource.SessionRecording,
		resource.Policy,
		resource.CredentialStore,
		resource.HostCatalog,
		resource.Worker,
		resource.Session,
		resource.Target,
	}
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.Scope{}},
		handlers.MaskSource{&pb.Scope{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove IdActions and CollectionActions package variables
	action.RegisterResource(resource.Scope, IdActions, CollectionActions)
}

// Service handles requests as described by the pbs.ScopeServiceServer interface.
type Service struct {
	pbs.UnsafeScopeServiceServer

	repoFn      common.IamRepoFactory
	kmsRepo     *kms.Kms
	maxPageSize uint
}

var _ pbs.ScopeServiceServer = (*Service)(nil)

// NewServiceFn returns a service which handles scope related requests to boundary.
var NewServiceFn = func(ctx context.Context, repo common.IamRepoFactory, kmsRepo *kms.Kms, maxPageSize uint) (pbs.ScopeServiceServer, error) {
	const op = "scopes.(Service).NewService"
	if util.IsNil(repo) {
		return &Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if kmsRepo == nil {
		return &Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing kms")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return &Service{repoFn: repo, kmsRepo: kmsRepo, maxPageSize: maxPageSize}, nil
}

// ListScopes implements the interface pbs.ScopeServiceServer.
func (s *Service) ListScopes(ctx context.Context, req *pbs.ListScopesRequest) (*pbs.ListScopesResponse, error) {
	const op = "scopes.(Service).ListScopes"
	if req.GetScopeId() == "" {
		req.ScopeId = scope.Global.String()
	}
	if err := validateListRequest(ctx, req); err != nil {
		return nil, err
	}

	// Hard-coding 'isRecursive' to true because list scope returns child scopes which requires
	// additional grants for those child-scopes (recursive) to calculate authorized_actions on the returned scope
	authResults := s.authResult(ctx, req.GetScopeId(), action.List, true)
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
		ctx, s.repoFn, authResults, req.GetScopeId(), resource.Scope, req.GetRecursive())
	if err != nil {
		return nil, err
	}

	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}

	var filterItemFn func(ctx context.Context, item *iam.Scope) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		filterItemFn = func(ctx context.Context, item *iam.Scope) (bool, error) {
			outputOpts, ok, err := newOutputOpts(ctx, item, authResults, scopeInfoMap)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
			pbItem, err := ToProto(ctx, item, outputOpts...)
			if err != nil {
				return false, err
			}
			return filter.Match(pbItem), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item *iam.Scope) (bool, error) {
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

	var listResp *pagination.ListResponse[*iam.Scope]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = iam.ListScopes(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Scope, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = iam.ListScopesPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListScopesRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = iam.ListScopesRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.Scope, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok, err := newOutputOpts(ctx, item, authResults, scopeInfoMap)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if !ok {
			continue
		}
		item, err := ToProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, item)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListScopesResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_SCOPE)
		if err != nil {
			return nil, err
		}
	}
	return resp, nil
}

// GetScopes implements the interface pbs.ScopeServiceServer.
func (s *Service) GetScope(ctx context.Context, req *pbs.GetScopeRequest) (*pbs.GetScopeResponse, error) {
	const op = "scopes.(Service).GetScope"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	p, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, p.GetPublicId(), idActionsById(p.GetPublicId())).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		scopeInfo := &pb.ScopeInfo{
			Id:            p.GetPublicId(),
			Type:          p.Type,
			Name:          p.GetName(),
			Description:   p.GetDescription(),
			ParentScopeId: p.GetParentId(),
		}
		collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, scopeCollectionTypeMapMap[p.Type], scopeInfo, "")
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := ToProto(ctx, p, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetScopeResponse{Item: item}, nil
}

// CreateScope implements the interface pbs.ScopeServiceServer.
func (s *Service) CreateScope(ctx context.Context, req *pbs.CreateScopeRequest) (*pbs.CreateScopeResponse, error) {
	const op = "scopes.(Service).CreateScope"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	p, err := s.createInRepo(ctx, authResults, req)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, p.GetPublicId(), idActionsById(p.GetPublicId())).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		scopeInfo := &pb.ScopeInfo{
			Id:            p.GetPublicId(),
			Type:          p.Type,
			Name:          p.GetName(),
			Description:   p.GetDescription(),
			ParentScopeId: p.GetParentId(),
		}
		collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, scopeCollectionTypeMapMap[p.Type], scopeInfo, "")
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := ToProto(ctx, p, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateScopeResponse{Item: item, Uri: fmt.Sprintf("scopes/%s", item.GetId())}, nil
}

// UpdateScope implements the interface pbs.ScopeServiceServer.
func (s *Service) UpdateScope(ctx context.Context, req *pbs.UpdateScopeRequest) (*pbs.UpdateScopeResponse, error) {
	const op = "scopes.(Service).UpdateScope"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	p, err := s.updateInRepo(ctx, authResults.Scope, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, p.GetPublicId(), idActionsById(p.GetPublicId())).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		scopeInfo := &pb.ScopeInfo{
			Id:            p.GetPublicId(),
			Type:          p.Type,
			Name:          p.GetName(),
			Description:   p.GetDescription(),
			ParentScopeId: p.GetParentId(),
		}
		collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, scopeCollectionTypeMapMap[p.Type], scopeInfo, "")
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := ToProto(ctx, p, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateScopeResponse{Item: item}, nil
}

// DeleteScope implements the interface pbs.ScopeServiceServer.
func (s *Service) DeleteScope(ctx context.Context, req *pbs.DeleteScopeRequest) (*pbs.DeleteScopeResponse, error) {
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

// ListKeys implements the interface pbs.ScopeServiceServer.
func (s *Service) ListKeys(ctx context.Context, req *pbs.ListKeysRequest) (*pbs.ListKeysResponse, error) {
	if req.GetId() == "" {
		req.Id = scope.Global.String()
	}
	if err := validateListKeysRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.ListScopeKeys, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	items, err := s.kmsRepo.ListKeys(ctx, req.GetId())
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, handlers.NotFoundErrorf("unknown scope_id %q", req.Id)
		}
		return nil, err
	}

	finalItems := make([]*pb.Key, 0, len(items))
	res := perms.Resource{
		Type: resource.Scope,
	}
	for _, item := range items {
		res.Id = item.Id
		res.ScopeId = item.Scope

		outputFields := authResults.FetchOutputFields(res, action.ListScopeKeys).SelfOrDefaults(authResults.UserId)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
		}

		protoItem, err := keyToProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, err
		}
		finalItems = append(finalItems, protoItem)
	}
	sortKeys(finalItems)
	return &pbs.ListKeysResponse{Items: finalItems}, nil
}

// RotateKeys implements the interface pbs.ScopeServiceServer.
func (s *Service) RotateKeys(ctx context.Context, req *pbs.RotateKeysRequest) (*pbs.RotateKeysResponse, error) {
	if req.GetScopeId() == "" {
		req.ScopeId = scope.Global.String()
	}
	if err := validateRotateKeysRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.RotateScopeKeys, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	if err := s.kmsRepo.RotateKeys(ctx, req.GetScopeId(), kms.WithRewrap(req.GetRewrap())); err != nil {
		return nil, err
	}

	return nil, nil
}

// ListKeyVersionDestructionJobs implements the interface pbs.ScopeServiceServer.
func (s *Service) ListKeyVersionDestructionJobs(ctx context.Context, req *pbs.ListKeyVersionDestructionJobsRequest) (*pbs.ListKeyVersionDestructionJobsResponse, error) {
	if req.GetScopeId() == "" {
		req.ScopeId = scope.Global.String()
	}
	if err := validateListKeyVersionDestructionJobsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.ListScopeKeyVersionDestructionJobs, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	jobs, err := s.kmsRepo.ListDataKeyVersionDestructionJobs(ctx, req.GetScopeId())
	if err != nil {
		return nil, err
	}
	res := perms.Resource{
		Type: resource.Scope,
	}
	finalJobs := make([]*pb.KeyVersionDestructionJob, 0, len(jobs))
	for _, job := range jobs {
		res.Id = job.ScopeId
		res.ScopeId = job.ScopeId

		outputFields := authResults.FetchOutputFields(res, action.ListScopeKeyVersionDestructionJobs).SelfOrDefaults(authResults.UserId)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
		}

		protoJob, err := destructionJobToProto(ctx, job, outputOpts...)
		if err != nil {
			return nil, err
		}
		finalJobs = append(finalJobs, protoJob)
	}
	return &pbs.ListKeyVersionDestructionJobsResponse{
		Items: finalJobs,
	}, nil
}

// DestroyKeyVersion implements the interface pbs.ScopeServiceServer.
func (s *Service) DestroyKeyVersion(ctx context.Context, req *pbs.DestroyKeyVersionRequest) (*pbs.DestroyKeyVersionResponse, error) {
	if req.GetScopeId() == "" {
		req.ScopeId = scope.Global.String()
	}
	if err := validateDestroyKeyVersionRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.DestroyScopeKeyVersion, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	destroyed, err := s.kmsRepo.DestroyKeyVersion(ctx, req.GetScopeId(), req.GetKeyVersionId())
	if err != nil {
		if errors.Match(errors.T(errors.KeyNotFound), err) {
			return nil, handlers.NotFoundErrorf("unknown key_version_id %q", req.KeyVersionId)
		}
		return nil, err
	}
	state := "completed"
	if !destroyed {
		state = "pending"
	}
	return &pbs.DestroyKeyVersionResponse{
		State: state,
	}, nil
}

// AttachStoragePolicy implements the interface pbs.ScopeServiceServer.
func (s *Service) AttachStoragePolicy(ctx context.Context, req *pbs.AttachStoragePolicyRequest) (*pbs.AttachStoragePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Policies are an Enterprise-only feature")
}

// DetachStoragePolicy implements the interface pbs.ScopeServiceServer.
func (s *Service) DetachStoragePolicy(ctx context.Context, req *pbs.DetachStoragePolicyRequest) (*pbs.DetachStoragePolicyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "Policies are an Enterprise-only feature")
}

func (s *Service) getFromRepo(ctx context.Context, id string) (*iam.Scope, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.LookupScope(ctx, id)
	if err != nil {
		return nil, err
	}
	if out == nil {
		return nil, handlers.NotFoundErrorf("Scope %q doesn't exist.", id)
	}
	return out, nil
}

func (s *Service) createInRepo(ctx context.Context, authResults auth.VerifyResults, req *pbs.CreateScopeRequest) (*iam.Scope, error) {
	const op = "scopes.(Service).createInRepo"
	item := req.GetItem()
	var opts []iam.Option
	if item.GetName() != nil {
		opts = append(opts, iam.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, iam.WithDescription(item.GetDescription().GetValue()))
	}
	opts = append(opts, iam.WithSkipAdminRoleCreation(req.GetSkipAdminRoleCreation()))
	opts = append(opts, iam.WithSkipDefaultRoleCreation(req.GetSkipDefaultRoleCreation()))

	parentScope := authResults.Scope
	var iamScope *iam.Scope
	var err error
	switch parentScope.GetType() {
	case scope.Global.String():
		iamScope, err = iam.NewOrg(ctx, opts...)
	case scope.Org.String():
		iamScope, err = iam.NewProject(ctx, parentScope.GetId(), opts...)
	}
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build new scope for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateScope(ctx, iamScope, authResults.UserId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create scope"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create scope but no error returned from repository.")
	}
	return out, nil
}

func (s *Service) updateInRepo(ctx context.Context, parentScope *pb.ScopeInfo, scopeId string, mask []string, item *pb.Scope) (*iam.Scope, error) {
	const op = "scope.(Service).updateInRepo"
	var opts []iam.Option
	var scopeDesc, scopeName, scopePrimaryAuthMethodId string
	if desc := item.GetDescription(); desc != nil {
		scopeDesc = desc.GetValue()
		opts = append(opts, iam.WithDescription(scopeDesc))
	}
	if name := item.GetName(); name != nil {
		scopeName = name.GetValue()
		opts = append(opts, iam.WithName(scopeName))
	}
	if primaryAuthMethodId := item.GetPrimaryAuthMethodId(); primaryAuthMethodId != nil {
		if !handlers.ValidId(handlers.Id(primaryAuthMethodId.GetValue()), globals.PasswordAuthMethodPrefix, globals.OidcAuthMethodPrefix, globals.LdapAuthMethodPrefix) {
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.", map[string]string{"primary_auth_method_id": "Improperly formatted identifier"})
		}
		scopePrimaryAuthMethodId = primaryAuthMethodId.GetValue()
		opts = append(opts, iam.WithPrimaryAuthMethodId(scopePrimaryAuthMethodId))
	}
	version := item.GetVersion()

	var iamScope *iam.Scope
	var err error
	switch {
	case scopeId == scope.Global.String():
		// boundary does not allow you to create a new global scope, so
		// we'll build the required scope by hand for the update.
		s := iam.AllocScope()
		s.PublicId = scopeId
		iamScope = &s
		iamScope.Description = scopeDesc
		iamScope.Name = scopeName
		iamScope.PrimaryAuthMethodId = scopePrimaryAuthMethodId
	case parentScope.GetType() == scope.Global.String():
		iamScope, err = iam.NewOrg(ctx, opts...)
	case parentScope.GetType() == scope.Org.String():
		iamScope, err = iam.NewProject(ctx, parentScope.GetId(), opts...)
	}
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build scope for update: %v.", err)
	}
	iamScope.PublicId = scopeId
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateScope(ctx, iamScope, version, dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update project"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Scope %q doesn't exist or incorrect version provided.", scopeId)
	}
	return out, nil
}

func (s *Service) deleteFromRepo(ctx context.Context, scopeId string) (bool, error) {
	const op = "scope.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteScope(ctx, scopeId)
	if err != nil {
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete scope"))
	}
	return rows > 0, nil
}

func sortKeys(keys []*pb.Key) {
	// We stable sort here even though the database may not return things in
	// sorted order, still nice to have them as consistent as possible.
	sort.SliceStable(keys, func(i, j int) bool {
		return keys[i].GetId() < keys[j].GetId()
	})
	// we also want to sort the key versions by version id so they are in
	// descending order (newest first)
	for _, key := range keys {
		sort.Slice(key.Versions, func(i, j int) bool {
			return key.Versions[i].Version > key.Versions[j].Version
		})
	}
}

func (s Service) authResult(ctx context.Context, id string, a action.Type, isRecursive bool) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive), auth.WithFetchAdditionalResourceGrants(additionalResourceGrants...)}
	switch a {
	case action.List, action.Create, action.ListScopeKeys, action.ListScopeKeyVersionDestructionJobs, action.DestroyScopeKeyVersion:
		parentId = id
		s, err := repo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if s == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	default:
		s, err := repo.LookupScope(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if s == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = s.GetParentId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, resource.Scope, opts...)
}

func ToProto(ctx context.Context, in *iam.Scope, opt ...handlers.Option) (*pb.Scope, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building scope proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Scope{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetParentId()
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = in.GetType()
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
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
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		out.AuthorizedCollectionActions = opts.WithAuthorizedCollectionActions
	}
	if outputFields.Has(globals.PrimaryAuthMethodIdField) && in.GetPrimaryAuthMethodId() != "" {
		out.PrimaryAuthMethodId = &wrapperspb.StringValue{Value: in.GetPrimaryAuthMethodId()}
	}
	if outputFields.Has(globals.StoragePolicyIdField) {
		out.StoragePolicyId = in.GetStoragePolicyId()
	}

	return &out, nil
}

func keyToProto(ctx context.Context, in wrappingKms.Key, opt ...handlers.Option) (*pb.Key, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building key proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Key{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.Id
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.KeyPurposeField) {
		out.Purpose = string(in.Purpose)
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = timestamppb.New(in.CreateTime)
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = string(in.Type)
	}
	if outputFields.Has(globals.KeyVersionsField) {
		for _, keyVersion := range in.Versions {
			out.Versions = append(out.Versions, &pb.KeyVersion{
				Id:          keyVersion.Id,
				Version:     uint32(keyVersion.Version),
				CreatedTime: timestamppb.New(keyVersion.CreateTime),
			})
		}
	}

	return &out, nil
}

func destructionJobToProto(ctx context.Context, in *kms.DataKeyVersionDestructionJobProgress, opt ...handlers.Option) (*pb.KeyVersionDestructionJob, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building data key version destruction job proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.KeyVersionDestructionJob{}
	if outputFields.Has(globals.KeyVersionIdField) {
		out.KeyVersionId = in.KeyId
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.CreatedTimeField) {
		out.CreatedTime = in.CreateTime.Timestamp
	}
	if outputFields.Has(globals.CompletedCountField) {
		out.CompletedCount = in.CompletedCount
	}
	if outputFields.Has(globals.TotalCountField) {
		out.TotalCount = in.TotalCount
	}
	if outputFields.Has(globals.StatusField) {
		out.Status = in.Status
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetScopeRequest) error {
	badFields := map[string]string{}
	id := req.GetId()
	switch {
	case id == scope.Global.String():
	case strings.HasPrefix(id, scope.Org.Prefix()):
		if !handlers.ValidId(handlers.Id(id), scope.Org.Prefix()) {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !handlers.ValidId(handlers.Id(id), scope.Project.Prefix()) {
			badFields["id"] = "Invalidly formatted scope id."
		}
	default:
		badFields["id"] = "Invalidly formatted scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateScopeRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		item := req.GetItem()
		if item.GetScopeId() == "" {
			badFields["scope_id"] = "Missing value for scope_id."
		}
		switch item.GetType() {
		case scope.Global.String():
			badFields["type"] = "Cannot create a global scope."
		case scope.Org.String():
			if !strings.EqualFold(scope.Global.String(), item.GetScopeId()) {
				badFields["type"] = "Org scopes can only be created under the global scope."
			}
		case scope.Project.String():
			if !handlers.ValidId(handlers.Id(item.GetScopeId()), scope.Org.Prefix()) {
				badFields["type"] = "Project scopes can only be created under an org scope."
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateScopeRequest) error {
	badFields := map[string]string{}
	id := req.GetId()
	switch {
	case id == scope.Global.String():
	case strings.HasPrefix(id, scope.Org.Prefix()):
		if !handlers.ValidId(handlers.Id(id), scope.Org.Prefix()) {
			badFields["id"] = "Invalidly formatted scope id."
		}
		if req.GetItem().GetType() != "" && !strings.EqualFold(scope.Org.String(), req.GetItem().GetType()) {
			badFields["type"] = "Cannot modify the resource type."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !handlers.ValidId(handlers.Id(id), scope.Project.Prefix()) {
			badFields["id"] = "Invalidly formatted scope id."
		}
		if req.GetItem().GetType() != "" && !strings.EqualFold(scope.Project.String(), req.GetItem().GetType()) {
			badFields["type"] = "Cannot modify the resource type."
		}
	default:
		badFields["id"] = "Invalidly formatted scope id."
	}
	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "UpdateMask not provided but is required to update a project."
	}

	item := req.GetItem()
	if item == nil {
		if len(badFields) > 0 {
			return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
		}
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if item.GetVersion() == 0 {
		badFields["version"] = "Existing resource version is required for an update."
	}
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetPrimaryAuthMethodId().GetValue() != "" && !handlers.ValidId(handlers.Id(item.GetPrimaryAuthMethodId().GetValue()), globals.PasswordAuthMethodPrefix, globals.OidcAuthMethodPrefix, globals.LdapAuthMethodPrefix) {
		badFields["primary_auth_method_id"] = "Improperly formatted identifier."
	}
	if item.GetName() != nil {
		trimmed := strings.TrimSpace(item.GetName().GetValue())
		switch {
		case trimmed == "":
			badFields["name"] = "Cannot set empty string as name"
		case !handlers.ValidName(trimmed):
			badFields["name"] = "Name contains unprintable characters"
		default:
			item.GetName().Value = trimmed
		}
	}
	if item.GetDescription() != nil {
		trimmed := strings.TrimSpace(item.GetDescription().GetValue())
		switch {
		case trimmed == "":
			badFields["description"] = "Cannot set empty string as description"
		case !handlers.ValidDescription(trimmed):
			badFields["description"] = "Description contains unprintable characters"
		default:
			item.GetDescription().Value = trimmed
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}

	return nil
}

func validateDeleteRequest(req *pbs.DeleteScopeRequest) error {
	badFields := map[string]string{}
	id := req.GetId()
	switch {
	case id == scope.Global.String():
		badFields["id"] = "Invalid to delete the global scope."
	case strings.HasPrefix(id, scope.Org.Prefix()):
		if !handlers.ValidId(handlers.Id(id), scope.Org.Prefix()) {
			badFields["id"] = "Invalidly formatted scope id."
		}
	case strings.HasPrefix(id, scope.Project.Prefix()):
		if !handlers.ValidId(handlers.Id(id), scope.Project.Prefix()) {
			badFields["id"] = "Invalidly formatted scope id."
		}
	default:
		badFields["id"] = "Invalidly formatted scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateListRequest(ctx context.Context, req *pbs.ListScopesRequest) error {
	badFields := map[string]string{}
	if req.GetScopeId() != scope.Global.String() && !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) {
		badFields["scope_id"] = "Must be 'global' or a valid org scope id when listing."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateListKeysRequest(req *pbs.ListKeysRequest) error {
	badFields := map[string]string{}
	if req.GetId() != scope.Global.String() && !handlers.ValidId(handlers.Id(req.GetId()), scope.Org.Prefix()) && !handlers.ValidId(handlers.Id(req.GetId()), scope.Project.Prefix()) {
		badFields["id"] = "Must be 'global', a valid org scope id or a valid project scope id when listing keys."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateRotateKeysRequest(req *pbs.RotateKeysRequest) error {
	badFields := map[string]string{}
	if req.GetScopeId() != scope.Global.String() && !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) && !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) {
		badFields["id"] = "Must be 'global', a valid org scope id or a valid project scope id when listing keys."
	}
	// other field is just a bool so can't be validated
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateListKeyVersionDestructionJobsRequest(req *pbs.ListKeyVersionDestructionJobsRequest) error {
	badFields := map[string]string{}
	if req.GetScopeId() != scope.Global.String() && !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) && !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) {
		badFields["scope_id"] = "Must be 'global', a valid org scope id or a valid project scope id when listing key version destruction jobs."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateDestroyKeyVersionRequest(req *pbs.DestroyKeyVersionRequest) error {
	badFields := map[string]string{}
	if req.GetScopeId() != scope.Global.String() && !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Org.Prefix()) && !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) {
		badFields["scope_id"] = "Must be 'global', a valid org scope id or a valid project scope id when destroying a key version."
	}
	if !handlers.ValidId(handlers.Id(req.GetKeyVersionId()), "kdkv", "krkv") {
		badFields["key_version_id"] = "Must be a valid KEK or DEK version ID."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func newOutputOpts(ctx context.Context, item *iam.Scope, authResults auth.VerifyResults, scopeInfoMap map[string]*pb.ScopeInfo) ([]handlers.Option, bool, error) {
	res := perms.Resource{
		Type:          resource.Scope,
		Id:            item.GetPublicId(),
		ScopeId:       item.GetParentId(),
		ParentScopeId: scopeInfoMap[item.GetParentId()].GetParentScopeId(),
	}

	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), idActionsById(item.GetPublicId()), auth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false, nil
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetParentId()]))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		scopeInfo := &pb.ScopeInfo{
			Id:            item.GetPublicId(),
			Type:          item.Type,
			Name:          item.GetName(),
			Description:   item.GetDescription(),
			ParentScopeId: item.GetParentId(),
		}
		collectionActions, err := auth.CalculateAuthorizedCollectionActions(ctx, authResults, scopeCollectionTypeMapMap[item.Type], scopeInfo, "")
		if err != nil {
			return nil, false, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	return outputOpts, true, nil
}

func idActionsById(id string) action.ActionSet {
	act := IdActions
	switch {
	case id == scope.Global.String():
		// Can't delete global so elide it
		act = action.Difference(act, action.NewActionSet(action.Delete))

	case strings.HasPrefix(id, fmt.Sprintf("%s_", scope.Project.Prefix())):
		// Can't attach/detach storage policy to projects
		act = action.Difference(act, action.NewActionSet(action.AttachStoragePolicy, action.DetachStoragePolicy))
	}

	return act
}
