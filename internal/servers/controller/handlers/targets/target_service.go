package targets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	stderrors "errors"
	"fmt"
	"math/rand"
	"net/url"
	"strings"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	"github.com/hashicorp/go-bexpr"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mitchellh/pointerstructure"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.AddHostSets,
		action.SetHostSets,
		action.RemoveHostSets,
		action.AddCredentialLibraries,
		action.SetCredentialLibraries,
		action.RemoveCredentialLibraries,
		action.AddCredentialSources,
		action.SetCredentialSources,
		action.RemoveCredentialSources,
		action.AuthorizeSession,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.TcpTarget{}}, handlers.MaskSource{&pb.Target{}, &pb.TcpTargetAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.TargetServiceServer interface.
type Service struct {
	pbs.UnimplementedTargetServiceServer

	repoFn           common.TargetRepoFactory
	iamRepoFn        common.IamRepoFactory
	serversRepoFn    common.ServersRepoFactory
	sessionRepoFn    common.SessionRepoFactory
	staticHostRepoFn common.StaticRepoFactory
	vaultCredRepoFn  common.VaultCredentialRepoFactory
	kmsCache         *kms.Kms
}

// NewService returns a target service which handles target related requests to boundary.
func NewService(
	kmsCache *kms.Kms,
	repoFn common.TargetRepoFactory,
	iamRepoFn common.IamRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	sessionRepoFn common.SessionRepoFactory,
	staticHostRepoFn common.StaticRepoFactory,
	vaultCredRepoFn common.VaultCredentialRepoFactory) (Service, error) {
	const op = "targets.NewService"
	if repoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing target repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	if serversRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing servers repository")
	}
	if sessionRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing session repository")
	}
	if staticHostRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing static host repository")
	}
	if vaultCredRepoFn == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing vault credential repository")
	}
	return Service{
		repoFn:           repoFn,
		iamRepoFn:        iamRepoFn,
		serversRepoFn:    serversRepoFn,
		sessionRepoFn:    sessionRepoFn,
		staticHostRepoFn: staticHostRepoFn,
		vaultCredRepoFn:  vaultCredRepoFn,
		kmsCache:         kmsCache,
	}, nil
}

var _ pbs.TargetServiceServer = Service{}

// ListTargets implements the interface pbs.TargetServiceServer.
func (s Service) ListTargets(ctx context.Context, req *pbs.ListTargetsRequest) (*pbs.ListTargetsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		// If it's forbidden, and it's a recursive request, and they're
		// successfully authenticated but just not authorized, keep going as we
		// may have authorization on downstream scopes.
		if authResults.Error == handlers.ForbiddenError() &&
			req.GetRecursive() &&
			authResults.AuthenticationFinished {
		} else {
			return nil, authResults.Error
		}
	}

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.Target, req.GetRecursive(), false)
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListTargetsResponse{}, nil
	}

	tl, err := s.listFromRepo(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	if len(tl) == 0 {
		return &pbs.ListTargetsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Target, 0, len(tl))
	res := perms.Resource{
		Type: resource.Target,
	}
	for _, item := range tl {
		res.Id = item.GetPublicId()
		res.ScopeId = item.GetScopeId()
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetScopeId()]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}

		item, err := toProto(ctx, item, nil, nil, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListTargetsResponse{Items: finalItems}, nil
}

// GetTargets implements the interface pbs.TargetServiceServer.
func (s Service) GetTarget(ctx context.Context, req *pbs.GetTargetRequest) (*pbs.GetTargetResponse, error) {
	const op = "targets.(Service).GetTarget"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetTargetResponse{Item: item}, nil
}

// CreateTarget implements the interface pbs.TargetServiceServer.
func (s Service) CreateTarget(ctx context.Context, req *pbs.CreateTargetRequest) (*pbs.CreateTargetResponse, error) {
	const op = "targets.(Service).CreateTarget"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.createInRepo(ctx, req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateTargetResponse{Item: item, Uri: fmt.Sprintf("targets/%s", item.GetId())}, nil
}

// UpdateTarget implements the interface pbs.TargetServiceServer.
func (s Service) UpdateTarget(ctx context.Context, req *pbs.UpdateTargetRequest) (*pbs.UpdateTargetResponse, error) {
	const op = "targets.(Service).UpdateTarget"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateTargetResponse{Item: item}, nil
}

// DeleteTarget implements the interface pbs.TargetServiceServer.
func (s Service) DeleteTarget(ctx context.Context, req *pbs.DeleteTargetRequest) (*pbs.DeleteTargetResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// AddTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) AddTargetHostSets(ctx context.Context, req *pbs.AddTargetHostSetsRequest) (*pbs.AddTargetHostSetsResponse, error) {
	const op = "targets.(Service).AddTargetHostSets"

	if err := validateAddSetsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.addHostSourcesInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddTargetHostSetsResponse{Item: item}, nil
}

// SetTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) SetTargetHostSets(ctx context.Context, req *pbs.SetTargetHostSetsRequest) (*pbs.SetTargetHostSetsResponse, error) {
	const op = "targets.(Service).SetTargetHostSets"

	if err := validateSetSetsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.setHostSourcesInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetTargetHostSetsResponse{Item: item}, nil
}

// RemoveTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) RemoveTargetHostSets(ctx context.Context, req *pbs.RemoveTargetHostSetsRequest) (*pbs.RemoveTargetHostSetsResponse, error) {
	const op = "targets.(Service).RemoveTargetHostSets"

	if err := validateRemoveSetsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.removeHostSourcesInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveTargetHostSetsResponse{Item: item}, nil
}

// AddTargetHostSources implements the interface pbs.TargetServiceServer.
func (s Service) AddTargetHostSources(ctx context.Context, req *pbs.AddTargetHostSourcesRequest) (*pbs.AddTargetHostSourcesResponse, error) {
	const op = "targets.(Service).AddTargetHostSources"

	if err := validateAddHostSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.addHostSourcesInRepo(ctx, req.GetId(), req.GetHostSourceIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddTargetHostSourcesResponse{Item: item}, nil
}

// SetTargetHostSources implements the interface pbs.TargetServiceServer.
func (s Service) SetTargetHostSources(ctx context.Context, req *pbs.SetTargetHostSourcesRequest) (*pbs.SetTargetHostSourcesResponse, error) {
	const op = "targets.(Service).SetTargetHostSources"

	if err := validateSetHostSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.setHostSourcesInRepo(ctx, req.GetId(), req.GetHostSourceIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetTargetHostSourcesResponse{Item: item}, nil
}

// RemoveTargetHostSources implements the interface pbs.TargetServiceServer.
func (s Service) RemoveTargetHostSources(ctx context.Context, req *pbs.RemoveTargetHostSourcesRequest) (*pbs.RemoveTargetHostSourcesResponse, error) {
	const op = "targets.(Service).RemoveTargetHostSets"

	if err := validateRemoveHostSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.removeHostSourcesInRepo(ctx, req.GetId(), req.GetHostSourceIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveTargetHostSourcesResponse{Item: item}, nil
}

// DEPRECATED: AddTargetCredentialLibraries implements the interface pbs.TargetServiceServer.
func (s Service) AddTargetCredentialLibraries(ctx context.Context, req *pbs.AddTargetCredentialLibrariesRequest) (*pbs.AddTargetCredentialLibrariesResponse, error) {
	const op = "targets.(Service).AddTargetCredentialLibraries"

	if err := validateAddLibrariesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddCredentialLibraries)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.addCredentialSourcesInRepo(ctx, req.GetId(), req.GetApplicationCredentialLibraryIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddTargetCredentialLibrariesResponse{Item: item}, nil
}

// DEPRECATED: SetTargetCredentialLibraries implements the interface pbs.TargetServiceServer.
func (s Service) SetTargetCredentialLibraries(ctx context.Context, req *pbs.SetTargetCredentialLibrariesRequest) (*pbs.SetTargetCredentialLibrariesResponse, error) {
	const op = "targets.(Service).SetTargetCredentialLibraries"

	if err := validateSetLibrariesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetCredentialLibraries)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.setCredentialSourcesInRepo(ctx, req.GetId(), req.GetApplicationCredentialLibraryIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetTargetCredentialLibrariesResponse{Item: item}, nil
}

// DEPRECATED: RemoveTargetCredentialLibraries implements the interface pbs.TargetServiceServer.
func (s Service) RemoveTargetCredentialLibraries(ctx context.Context, req *pbs.RemoveTargetCredentialLibrariesRequest) (*pbs.RemoveTargetCredentialLibrariesResponse, error) {
	const op = "targets.(Service).RemoveTargetCredentialLibraries"

	if err := validateRemoveLibrariesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveCredentialLibraries)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.removeCredentialSourcesInRepo(ctx, req.GetId(), req.GetApplicationCredentialLibraryIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveTargetCredentialLibrariesResponse{Item: item}, nil
}

// AddTargetCredentialSources implements the interface pbs.TargetServiceServer.
func (s Service) AddTargetCredentialSources(ctx context.Context, req *pbs.AddTargetCredentialSourcesRequest) (*pbs.AddTargetCredentialSourcesResponse, error) {
	const op = "targets.(Service).AddTargetCredentialSources"

	if err := validateAddCredentialSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddCredentialSources)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.addCredentialSourcesInRepo(ctx, req.GetId(), req.GetApplicationCredentialSourceIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.AddTargetCredentialSourcesResponse{Item: item}, nil
}

// SetTargetCredentialSources implements the interface pbs.TargetServiceServer.
func (s Service) SetTargetCredentialSources(ctx context.Context, req *pbs.SetTargetCredentialSourcesRequest) (*pbs.SetTargetCredentialSourcesResponse, error) {
	const op = "targets.(Service).SetTargetCredentialSources"

	if err := validateSetCredentialSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetCredentialSources)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.setCredentialSourcesInRepo(ctx, req.GetId(), req.GetApplicationCredentialSourceIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetTargetCredentialSourcesResponse{Item: item}, nil
}

// RemoveTargetCredentialSources implements the interface pbs.TargetServiceServer.
func (s Service) RemoveTargetCredentialSources(ctx context.Context, req *pbs.RemoveTargetCredentialSourcesRequest) (*pbs.RemoveTargetCredentialSourcesResponse, error) {
	const op = "targets.(Service).RemoveTargetCredentialSources"

	if err := validateRemoveCredentialSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveCredentialSources)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, ts, cl, err := s.removeCredentialSourcesInRepo(ctx, req.GetId(), req.GetApplicationCredentialSourceIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}

	outputFields, ok := requests.OutputFields(ctx)
	if !ok {
		return nil, errors.New(ctx, errors.Internal, op, "no request context found")
	}

	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, t, ts, cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveTargetCredentialSourcesResponse{Item: item}, nil
}

func (s Service) AuthorizeSession(ctx context.Context, req *pbs.AuthorizeSessionRequest) (*pbs.AuthorizeSessionResponse, error) {
	const op = "targets.(Service).AuthorizeSession"
	if err := validateAuthorizeSessionRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AuthorizeSession,
		target.WithName(req.GetName()),
		target.WithScopeId(req.GetScopeId()),
		target.WithScopeName(req.GetScopeName()),
	)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	if authResults.RoundTripValue == nil {
		return nil, stderrors.New("authorize session: expected to get a target back from auth results")
	}
	t, ok := authResults.RoundTripValue.(target.Target)
	if !ok {
		return nil, stderrors.New("authorize session: round tripped auth results value is not a target")
	}
	if t == nil {
		return nil, stderrors.New("authorize session: round tripped target is nil")
	}

	// This could happen if, say, u_recovery was used or u_anon was granted. But
	// don't allow it. It's one thing if grants give access to resources within
	// Boundary, even if those could eventually be used to provide an unintended
	// user access to a remote system. It's quite another to enable anonymous
	// access directly to a remote system.
	//
	// Note that even if u_anon or u_auth are given grants we can still validate
	// a token! So this is just checking that a valid token was provided. The
	// actual reality of this works out to excluding:
	//
	// * True anonymous access (no token provided and u_anon)
	//
	// * u_recovery access (which is fine, recovery is meant for recovering
	// system state, no real reason to allow it to then connect to systems)
	if authResults.AuthTokenId == "" {
		return nil, handlers.ForbiddenError()
	}

	// Get the target information
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	t, hostSources, libs, err := repo.LookupTarget(ctx, t.GetPublicId())
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, handlers.NotFoundErrorf("Target %q not found.", t.GetPublicId())
		}
		return nil, err
	}
	if t == nil {
		return nil, handlers.NotFoundErrorf("Target %q not found.", t.GetPublicId())
	}

	// Instantiate some repos
	sessionRepo, err := s.sessionRepoFn()
	if err != nil {
		return nil, err
	}
	serversRepo, err := s.serversRepoFn()
	if err != nil {
		return nil, err
	}

	// First ensure we can actually service a request, that is, we have workers
	// available (after any filtering). WorkerInfo only contains the address;
	// worker IDs below is used to contain their IDs in the same order. This is
	// used to fetch tags for filtering. But we avoid allocation unless we
	// actually need it.
	var workers []*pb.WorkerInfo
	var workerIds []string
	hasWorkerFilter := len(t.GetWorkerFilter()) > 0
	servers, err := serversRepo.ListServers(ctx, servers.ServerTypeWorker)
	if err != nil {
		return nil, err
	}
	for _, v := range servers {
		if hasWorkerFilter {
			workerIds = append(workerIds, v.GetPrivateId())
		}
		workers = append(workers, &pb.WorkerInfo{Address: v.Address})
	}

	if hasWorkerFilter && len(workerIds) > 0 {
		finalWorkers := make([]*pb.WorkerInfo, 0, len(workers))
		// Fetch the tags for the given worker IDs
		tags, err := serversRepo.ListTagsForServers(ctx, workerIds)
		if err != nil {
			return nil, err
		}
		// Build the map for filtering. This is similar to the filter map we
		// built from the worker config, but with one extra level: a map of the
		// worker's ID to its filter map.
		tagMap := make(map[string]map[string][]string)
		for _, tag := range tags {
			currWorkerMap := tagMap[tag.ServerId]
			if currWorkerMap == nil {
				currWorkerMap = make(map[string][]string)
				tagMap[tag.ServerId] = currWorkerMap
			}
			currWorkerMap[tag.Key] = append(currWorkerMap[tag.Key], tag.Value)
			// We don't need to reinsert after the fact because maps are
			// reference types, so we don't need to re-insert into tagMap
		}

		// Create the evaluator
		eval, err := bexpr.CreateEvaluator(t.GetWorkerFilter())
		if err != nil {
			return nil, err
		}

		// Iterate through the known worker IDs, and evaluate. If evaluation
		// returns true, add to the final worker slice, which is assigned back
		// to workers after this.
		for i, worker := range workerIds {
			filterInput := map[string]interface{}{
				"name": worker,
				"tags": tagMap[worker],
			}
			ok, err := eval.Evaluate(filterInput)
			if err != nil && !stderrors.Is(err, pointerstructure.ErrNotFound) {
				return nil, handlers.ApiErrorWithCodeAndMessage(
					codes.FailedPrecondition,
					fmt.Sprintf("Worker filter expression evaluation resulted in error: %s", err))
			}
			if ok {
				finalWorkers = append(finalWorkers, workers[i])
			}
		}
		workers = finalWorkers
	}
	if len(workers) == 0 {
		return nil, handlers.ApiErrorWithCodeAndMessage(
			codes.FailedPrecondition,
			"No workers are available to handle this session, or all have been filtered.")
	}

	// First, fetch all available hosts. Unless one was chosen in the request,
	// we will pick one at random.
	type compoundHost struct {
		hostSetId string
		hostId    string
	}

	var chosenId *compoundHost
	requestedId := req.GetHostId()
	staticHostRepo, err := s.staticHostRepoFn()
	if err != nil {
		return nil, err
	}

	hostIds := make([]compoundHost, 0, len(hostSources)*10)

HostSourceIterationLoop:
	for _, hSource := range hostSources {
		hsId := hSource.Id()
		switch host.SubtypeFromId(hsId) {
		case static.Subtype:
			_, hosts, err := staticHostRepo.LookupSet(ctx, hsId)
			if err != nil {
				return nil, err
			}
			for _, host := range hosts {
				compoundId := compoundHost{hostSetId: hsId, hostId: host.PublicId}
				hostIds = append(hostIds, compoundId)
				if host.PublicId == requestedId {
					chosenId = &compoundId
					break HostSourceIterationLoop
				}
			}
		}
	}
	if requestedId != "" && chosenId == nil {
		// We didn't find it
		return nil, handlers.InvalidArgumentErrorf(
			"Errors in provided fields.",
			map[string]string{
				"host_id": "The requested host id is not available.",
			})
	}
	if chosenId == nil {
		if len(hostIds) == 0 {
			// No hosts were found, error
			return nil, handlers.NotFoundErrorf("No hosts found from available target host sources.")
		}
		chosenId = &hostIds[rand.Intn(len(hostIds))]
	}

	// Generate the endpoint URL
	endpointUrl := &url.URL{
		Scheme: t.GetType(),
	}
	defaultPort := t.GetDefaultPort()
	var endpointHost string
	switch host.SubtypeFromId(chosenId.hostId) {
	case static.Subtype:
		h, err := staticHostRepo.LookupHost(ctx, chosenId.hostId)
		if err != nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, "errors looking up host")
		}
		endpointHost = h.Address
		if endpointHost == "" {
			return nil, stderrors.New("host had empty address")
		}
	}
	if defaultPort != 0 {
		endpointUrl.Host = fmt.Sprintf("%s:%d", endpointHost, defaultPort)
	} else {
		endpointUrl.Host = endpointHost
	}

	var reqs []credential.Request
	var dynCreds []*session.DynamicCredential
	for _, l := range libs {
		reqs = append(reqs, credential.Request{
			SourceId: l.Id(),
			Purpose:  l.CredentialPurpose(),
		})
		dynCreds = append(dynCreds, session.NewDynamicCredential(l.Id(), l.CredentialPurpose()))
	}

	expTime := timestamppb.Now()
	expTime.Seconds += int64(t.GetSessionMaxSeconds())
	sessionComposition := session.ComposedOf{
		UserId:             authResults.UserId,
		HostId:             chosenId.hostId,
		TargetId:           t.GetPublicId(),
		HostSetId:          chosenId.hostSetId,
		AuthTokenId:        authResults.AuthTokenId,
		ScopeId:            authResults.Scope.Id,
		Endpoint:           endpointUrl.String(),
		ExpirationTime:     &timestamp.Timestamp{Timestamp: expTime},
		ConnectionLimit:    t.GetSessionConnectionLimit(),
		WorkerFilter:       t.GetWorkerFilter(),
		DynamicCredentials: dynCreds,
	}

	sess, err := session.New(sessionComposition)
	if err != nil {
		return nil, err
	}
	wrapper, err := s.kmsCache.GetWrapper(ctx, authResults.Scope.Id, kms.KeyPurposeSessions)
	if err != nil {
		return nil, err
	}
	sess, privKey, err := sessionRepo.CreateSession(ctx, wrapper, sess)
	if err != nil {
		return nil, err
	}

	var cs []credential.Dynamic
	if len(reqs) > 0 {
		credRepo, err := s.vaultCredRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cs, err = credRepo.Issue(ctx, sess.GetPublicId(), reqs)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	var creds []*pb.SessionCredential
	for _, c := range cs {
		l := c.Library()
		secret := c.Secret()
		// TODO: Access the json directly from the vault response instead of re-marshalling it.
		jSecret, err := json.Marshal(secret)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("marshalling secret to json"))
		}
		var sSecret *structpb.Struct
		switch secret.(type) {
		case map[string]interface{}:
			// In this case we actually have to re-decode it. The proto wrappers
			// choke on json.Number and at the time I'm writing this I don't
			// have time to write a walk function to dig through with reflect
			// and find all json.Numbers and replace them. So we eat the
			// inefficiency. So note that we are specifically _not_ using a
			// decoder with UseNumber here.
			var dSecret map[string]interface{}
			if err := json.Unmarshal(jSecret, &dSecret); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("decoding json for proto marshaling"))
			}
			sSecret, err = structpb.NewStruct(dSecret)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("creating proto struct for secret"))
			}
		}
		creds = append(creds, &pb.SessionCredential{
			CredentialLibrary: &pb.CredentialLibrary{
				Id:                l.GetPublicId(),
				Name:              l.GetName(),
				Description:       l.GetDescription(),
				CredentialStoreId: l.GetStoreId(),
				Type:              credential.SubtypeFromId(l.GetPublicId()).String(),
			},
			Secret: &pb.SessionSecret{
				Raw:     base64.StdEncoding.EncodeToString(jSecret),
				Decoded: sSecret,
			},
		})
	}

	sad := &pb.SessionAuthorizationData{
		SessionId:       sess.PublicId,
		TargetId:        t.GetPublicId(),
		Scope:           authResults.Scope,
		CreatedTime:     sess.CreateTime.GetTimestamp(),
		Type:            t.GetType(),
		Certificate:     sess.Certificate,
		PrivateKey:      privKey,
		HostId:          chosenId.hostId,
		Endpoint:        endpointUrl.String(),
		WorkerInfo:      workers,
		ConnectionLimit: t.GetSessionConnectionLimit(),
	}
	marshaledSad, err := proto.Marshal(sad)
	if err != nil {
		return nil, err
	}
	encodedMarshaledSad := base58.FastBase58Encoding(marshaledSad)

	ret := &pb.SessionAuthorization{
		SessionId:          sess.PublicId,
		TargetId:           t.GetPublicId(),
		Scope:              authResults.Scope,
		CreatedTime:        sess.CreateTime.GetTimestamp(),
		Type:               t.GetType(),
		AuthorizationToken: string(encodedMarshaledSad),
		UserId:             authResults.UserId,
		HostId:             chosenId.hostId,
		HostSetId:          chosenId.hostSetId,
		Endpoint:           endpointUrl.String(),
		Credentials:        creds,
	}
	return &pbs.AuthorizeSessionResponse{Item: ret}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	u, hs, cl, err := repo.LookupTarget(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
		}
		return nil, nil, nil, err
	}
	if u == nil {
		return nil, nil, nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
	}
	return u, hs, cl, nil
}

func (s Service) createInRepo(ctx context.Context, item *pb.Target) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).createInRepo"
	opts := []target.Option{target.WithName(item.GetName().GetValue())}
	if item.GetDescription() != nil {
		opts = append(opts, target.WithDescription(item.GetDescription().GetValue()))
	}
	if item.GetSessionMaxSeconds() != nil {
		opts = append(opts, target.WithSessionMaxSeconds(item.GetSessionMaxSeconds().GetValue()))
	}
	if item.GetSessionConnectionLimit() != nil {
		opts = append(opts, target.WithSessionConnectionLimit(item.GetSessionConnectionLimit().GetValue()))
	}
	if item.GetWorkerFilter() != nil {
		opts = append(opts, target.WithWorkerFilter(item.GetWorkerFilter().GetValue()))
	}
	tcpAttrs := &pb.TcpTargetAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), tcpAttrs); err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if tcpAttrs.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(tcpAttrs.GetDefaultPort().GetValue()))
	}
	u, err := target.NewTcpTarget(item.GetScopeId(), opts...)
	if err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build target for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, hs, cl, err := repo.CreateTcpTarget(ctx, u)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create target but no error returned from repository.")
	}
	return out, hs, cl, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Target) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).updateInRepo"
	var opts []target.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, target.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, target.WithName(name.GetValue()))
	}
	if item.GetSessionMaxSeconds() != nil {
		opts = append(opts, target.WithSessionMaxSeconds(item.GetSessionMaxSeconds().GetValue()))
	}
	if item.GetSessionConnectionLimit() != nil {
		opts = append(opts, target.WithSessionConnectionLimit(item.GetSessionConnectionLimit().GetValue()))
	}
	if filter := item.GetWorkerFilter(); filter != nil {
		opts = append(opts, target.WithWorkerFilter(item.GetWorkerFilter().GetValue()))
	}
	tcpAttrs := &pb.TcpTargetAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), tcpAttrs); err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if tcpAttrs.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(tcpAttrs.GetDefaultPort().GetValue()))
	}
	version := item.GetVersion()
	u, err := target.NewTcpTarget(scopeId, opts...)
	if err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build target for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, hs, cl, rowsUpdated, err := repo.UpdateTcpTarget(ctx, u, version, dbMask)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target"))
	}
	if rowsUpdated == 0 {
		return nil, nil, nil, handlers.NotFoundErrorf("Target %q not found or incorrect version provided.", id)
	}
	return out, hs, cl, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "targets.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteTarget(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete target"))
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]target.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListTargets(ctx, target.WithScopeIds(scopeIds))
	if err != nil {
		return nil, err
	}
	return ul, nil
}

func (s Service) addHostSourcesInRepo(ctx context.Context, targetId string, hostSourceIds []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, hs, cl, err := repo.AddTargetHostSources(ctx, targetId, version, strutil.RemoveDuplicates(hostSourceIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add host sources to target: %v.", err)
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after adding host sources to it.")
	}
	return out, hs, cl, nil
}

func (s Service) setHostSourcesInRepo(ctx context.Context, targetId string, hostSourceIds []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).setSourcesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, _, _, err = repo.SetTargetHostSources(ctx, targetId, version, strutil.RemoveDuplicates(hostSourceIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set host sources in target: %v.", err)
	}

	out, hs, cl, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after setting host sources"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after setting host sources for it.")
	}
	return out, hs, cl, nil
}

func (s Service) removeHostSourcesInRepo(ctx context.Context, targetId string, hostSourceIds []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).removeHostSourcesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = repo.DeleteTargetHostSources(ctx, targetId, version, strutil.RemoveDuplicates(hostSourceIds, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove host sources from target: %v.", err)
	}
	out, hs, cl, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after removing host sources"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after removing host sources from it.")
	}
	return out, hs, cl, nil
}

func (s Service) addCredentialSourcesInRepo(ctx context.Context, targetId string, ids []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, hs, credSources, err := repo.AddTargetCredentialSources(ctx, targetId, version, strutil.RemoveDuplicates(ids, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add credential sources to target: %v.", err)
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after adding credential sources to it.")
	}
	return out, hs, credSources, nil
}

func (s Service) setCredentialSourcesInRepo(ctx context.Context, targetId string, ids []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).setCredentialSourcesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, _, _, err = repo.SetTargetCredentialSources(ctx, targetId, version, strutil.RemoveDuplicates(ids, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set credential sources in target: %v.", err)
	}

	out, hs, credSources, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after setting credential sources"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after setting credential sources for it.")
	}
	return out, hs, credSources, nil
}

func (s Service) removeCredentialSourcesInRepo(ctx context.Context, targetId string, ids []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).removeCredentialSourcesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = repo.DeleteTargetCredentialSources(ctx, targetId, version, strutil.RemoveDuplicates(ids, false))
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove credential sources from target: %v.", err)
	}
	out, hs, credSources, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after removing credential sources"))
	}
	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after removing credential sources from it.")
	}
	return out, hs, credSources, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type, lookupOpt ...target.Option) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	var t target.Target
	opts := []auth.Option{auth.WithType(resource.Target), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
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
		t, _, _, err = repo.LookupTarget(ctx, id, lookupOpt...)
		if err != nil {
			// TODO: Fix this with new/better error handling
			if strings.Contains(err.Error(), "more than one row returned by a subquery") {
				res.Error = handlers.ApiErrorWithCodeAndMessage(codes.FailedPrecondition, "Scope name is ambiguous (matches more than one scope), use scope ID with target name instead, or use target ID.")
			} else {
				res.Error = err
			}
			return res
		}
		if t == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		id = t.GetPublicId()
		parentId = t.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	ret := auth.Verify(ctx, opts...)
	ret.RoundTripValue = t
	return ret
}

func toProto(ctx context.Context, in target.Target, hostSources []target.HostSource, credSources []target.CredentialSource, opt ...handlers.Option) (*pb.Target, error) {
	const op = "target_service.toProto"
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building target proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Target{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = target.TcpTargetType.String()
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
	if outputFields.Has(globals.SessionMaxSecondsField) {
		out.SessionMaxSeconds = wrapperspb.UInt32(in.GetSessionMaxSeconds())
	}
	if outputFields.Has(globals.SessionConnectionLimitField) {
		out.SessionConnectionLimit = wrapperspb.Int32(in.GetSessionConnectionLimit())
	}
	if outputFields.Has(globals.WorkerFilterField) && in.GetWorkerFilter() != "" {
		out.WorkerFilter = wrapperspb.String(in.GetWorkerFilter())
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.HostSetIdsField) {
		for _, hs := range hostSources {
			out.HostSetIds = append(out.HostSetIds, hs.Id())
		}
	}
	if outputFields.Has(globals.HostSourceIdsField) {
		for _, hs := range hostSources {
			out.HostSourceIds = append(out.HostSourceIds, hs.Id())
		}
	}
	if outputFields.Has(globals.HostSetsField) {
		for _, hs := range hostSources {
			out.HostSets = append(out.HostSets, &pb.HostSet{
				Id:            hs.Id(),
				HostCatalogId: hs.HostCatalogId(),
			})
		}
	}
	if outputFields.Has(globals.HostSourcesField) {
		for _, hs := range hostSources {
			out.HostSources = append(out.HostSources, &pb.HostSource{
				Id:            hs.Id(),
				HostCatalogId: hs.HostCatalogId(),
			})
		}
	}
	if outputFields.Has(globals.ApplicationCredentialLibraryIdsField) {
		for _, cs := range credSources {
			out.ApplicationCredentialLibraryIds = append(out.ApplicationCredentialLibraryIds, cs.Id())
		}
	}
	if outputFields.Has(globals.ApplicationCredentialSourceIdsField) {
		for _, cs := range credSources {
			out.ApplicationCredentialSourceIds = append(out.ApplicationCredentialSourceIds, cs.Id())
		}
	}
	if outputFields.Has(globals.ApplicationCredentialLibrariesField) {
		for _, cs := range credSources {
			switch credential.Purpose(cs.CredentialPurpose()) {
			case credential.ApplicationPurpose:
				out.ApplicationCredentialLibraries = append(out.ApplicationCredentialLibraries, &pb.CredentialLibrary{
					Id:                cs.Id(),
					CredentialStoreId: cs.CredentialStoreId(),
				})
			case credential.IngressPurpose, credential.EgressPurpose:
				// TODO: When we support other purposes add them to different fields here.
			default:
				return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unrecognized purpose %q for credential source on target", cs.CredentialPurpose()))
			}
		}
	}
	if outputFields.Has(globals.ApplicationCredentialSourcesField) {
		for _, cs := range credSources {
			switch credential.Purpose(cs.CredentialPurpose()) {
			case credential.ApplicationPurpose:
				out.ApplicationCredentialSources = append(out.ApplicationCredentialSources, &pb.CredentialSource{
					Id:                cs.Id(),
					CredentialStoreId: cs.CredentialStoreId(),
				})
			case credential.IngressPurpose, credential.EgressPurpose:
				// TODO: When we support other purposes add them to different fields here.
			default:
				return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unrecognized purpose %q for credential source on target", cs.CredentialPurpose()))
			}
		}
	}
	if outputFields.Has(globals.AttributesField) {
		attrs := &pb.TcpTargetAttributes{}
		if in.GetDefaultPort() > 0 {
			attrs.DefaultPort = &wrappers.UInt32Value{Value: in.GetDefaultPort()}
		}
		st, err := handlers.ProtoToStruct(attrs)
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building password attribute struct: %v", err)
		}
		out.Attributes = st
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetTargetRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, target.TcpTargetPrefix)
}

func validateCreateRequest(req *pbs.CreateTargetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Project.Prefix()) {
			badFields[globals.ScopeIdField] = "This field is required to have a properly formatted project scope id."
		}
		if req.GetItem().GetName() == nil || req.GetItem().GetName().GetValue() == "" {
			badFields[globals.NameField] = "This field is required."
		}
		if req.GetItem().GetSessionConnectionLimit() != nil {
			val := req.GetItem().GetSessionConnectionLimit().GetValue()
			switch {
			case val == -1:
			case val > 0:
			default:
				badFields[globals.SessionConnectionLimitField] = "This must be -1 (unlimited) or greater than zero."
			}
		}
		if req.GetItem().GetSessionMaxSeconds() != nil && req.GetItem().GetSessionMaxSeconds().GetValue() == 0 {
			badFields[globals.SessionMaxSecondsField] = "This must be greater than zero."
		}
		switch target.SubtypeFromType(req.GetItem().GetType()) {
		case target.TcpSubtype:
			tcpAttrs := &pb.TcpTargetAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), tcpAttrs); err != nil {
				badFields[globals.AttributesField] = "Attribute fields do not match the expected format."
			}
			if tcpAttrs.GetDefaultPort() != nil && tcpAttrs.GetDefaultPort().GetValue() == 0 {
				badFields["attributes.default_port"] = "This optional field cannot be set to 0."
			}
		}
		switch req.GetItem().GetType() {
		case target.TcpTargetType.String():
		case "":
			badFields[globals.TypeField] = "This is a required field."
		default:
			badFields[globals.TypeField] = "Unknown type provided."
		}
		if filter := req.GetItem().GetWorkerFilter(); filter != nil {
			if _, err := bexpr.CreateEvaluator(filter.GetValue()); err != nil {
				badFields[globals.WorkerFilterField] = "Unable to successfully parse filter expression."
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateTargetRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), globals.NameField) && req.GetItem().GetName().GetValue() == "" {
			badFields[globals.NameField] = "This field cannot be set to empty."
		}
		if req.GetItem().GetSessionConnectionLimit() != nil {
			val := req.GetItem().GetSessionConnectionLimit().GetValue()
			switch {
			case val == -1:
			case val > 0:
			default:
				badFields[globals.SessionConnectionLimitField] = "This must be -1 (unlimited) or greater than zero."
			}
		}
		if req.GetItem().GetSessionMaxSeconds() != nil && req.GetItem().GetSessionMaxSeconds().GetValue() == 0 {
			badFields[globals.SessionMaxSecondsField] = "This must be greater than zero."
		}
		switch target.SubtypeFromId(req.GetItem().GetType()) {
		case target.TcpSubtype:
			if req.GetItem().GetType() != "" && target.SubtypeFromType(req.GetItem().GetType()) != target.TcpSubtype {
				badFields[globals.TypeField] = "Cannot modify the resource type."
			}
			tcpAttrs := &pb.TcpTargetAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), tcpAttrs); err != nil {
				badFields[globals.AttributesField] = "Attribute fields do not match the expected format."
			}
			if tcpAttrs.GetDefaultPort() != nil && tcpAttrs.GetDefaultPort().GetValue() == 0 {
				badFields["attributes.default_port"] = "This optional field cannot be set to 0."
			}
		}
		if filter := req.GetItem().GetWorkerFilter(); filter != nil {
			if _, err := bexpr.CreateEvaluator(filter.GetValue()); err != nil {
				badFields[globals.WorkerFilterField] = "Unable to successfully parse filter expression."
			}
		}
		return badFields
	}, target.TcpTargetPrefix)
}

func validateDeleteRequest(req *pbs.DeleteTargetRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, target.TcpTargetPrefix)
}

func validateListRequest(req *pbs.ListTargetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		!req.GetRecursive() {
		badFields[globals.ScopeIdField] = "This field must be a valid project scope ID or the list operation must be recursive."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddSetsRequest(req *pbs.AddTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostSetIds()) == 0 {
		badFields[globals.HostSetIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostSetIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostSetPrefix) {
			badFields[globals.HostSetIdsField] = fmt.Sprintf("Incorrectly formatted host set identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetSetsRequest(req *pbs.SetTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for _, id := range req.GetHostSetIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostSetPrefix) {
			badFields[globals.HostSetIdsField] = fmt.Sprintf("Incorrectly formatted host set identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveSetsRequest(req *pbs.RemoveTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostSetIds()) == 0 {
		badFields[globals.HostSetIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostSetIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostSetPrefix) {
			badFields[globals.HostSetIdsField] = fmt.Sprintf("Incorrectly formatted host set identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAddHostSourcesRequest(req *pbs.AddTargetHostSourcesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostSourceIds()) == 0 {
		badFields[globals.HostSourceIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostSourceIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostSetPrefix) {
			badFields[globals.HostSourceIdsField] = fmt.Sprintf("Incorrectly formatted host source identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetHostSourcesRequest(req *pbs.SetTargetHostSourcesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for _, id := range req.GetHostSourceIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostSetPrefix) {
			badFields[globals.HostSourceIdsField] = fmt.Sprintf("Incorrectly formatted host source identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveHostSourcesRequest(req *pbs.RemoveTargetHostSourcesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostSourceIds()) == 0 {
		badFields[globals.HostSourceIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostSourceIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostSetPrefix) {
			badFields[globals.HostSourceIdsField] = fmt.Sprintf("Incorrectly formatted host source identifier %q.", id)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAddLibrariesRequest(req *pbs.AddTargetCredentialLibrariesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetApplicationCredentialLibraryIds()) == 0 {
		badFields[globals.ApplicationCredentialLibraryIdsField] = "Must be non-empty."
	}
	for _, cl := range req.GetApplicationCredentialLibraryIds() {
		if !handlers.ValidId(handlers.Id(cl), vault.CredentialLibraryPrefix) {
			badFields[globals.ApplicationCredentialLibraryIdsField] = fmt.Sprintf("Incorrectly formatted credential library identifier %q.", cl)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetLibrariesRequest(req *pbs.SetTargetCredentialLibrariesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for _, cl := range req.GetApplicationCredentialLibraryIds() {
		if !handlers.ValidId(handlers.Id(cl), vault.CredentialLibraryPrefix) {
			badFields[globals.ApplicationCredentialLibraryIdsField] = fmt.Sprintf("Incorrectly formatted credential library identifier %q.", cl)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveLibrariesRequest(req *pbs.RemoveTargetCredentialLibrariesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetApplicationCredentialLibraryIds()) == 0 {
		badFields[globals.ApplicationCredentialLibraryIdsField] = "Must be non-empty."
	}
	for _, cl := range req.GetApplicationCredentialLibraryIds() {
		if !handlers.ValidId(handlers.Id(cl), vault.CredentialLibraryPrefix) {
			badFields[globals.ApplicationCredentialLibraryIdsField] = fmt.Sprintf("Incorrectly formatted credential library identifier %q.", cl)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAddCredentialSourcesRequest(req *pbs.AddTargetCredentialSourcesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetApplicationCredentialSourceIds()) == 0 {
		badFields[globals.ApplicationCredentialSourceIdsField] = "Must be non-empty."
	}
	for _, cl := range req.GetApplicationCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl), vault.CredentialLibraryPrefix) {
			badFields[globals.ApplicationCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetCredentialSourcesRequest(req *pbs.SetTargetCredentialSourcesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for _, cl := range req.GetApplicationCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl), vault.CredentialLibraryPrefix) {
			badFields[globals.ApplicationCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveCredentialSourcesRequest(req *pbs.RemoveTargetCredentialSourcesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetApplicationCredentialSourceIds()) == 0 {
		badFields[globals.ApplicationCredentialLibraryIdsField] = "Must be non-empty."
	}
	for _, cl := range req.GetApplicationCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl), vault.CredentialLibraryPrefix) {
			badFields[globals.ApplicationCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateAuthorizeSessionRequest(req *pbs.AuthorizeSessionRequest) error {
	badFields := map[string]string{}
	nameEmpty := req.GetName() == ""
	scopeIdEmpty := req.GetScopeId() == ""
	scopeNameEmpty := req.GetScopeName() == ""
	if nameEmpty {
		if !handlers.ValidId(handlers.Id(req.GetId()), target.TcpTargetPrefix) {
			badFields[globals.IdField] = "Incorrectly formatted identifier."
		}
		if !scopeIdEmpty {
			badFields[globals.ScopeIdField] = "Scope ID provided when target name was empty."
		}
		if !scopeNameEmpty {
			badFields[globals.ScopeIdField] = "Scope name provided when target name was empty."
		}
	} else {
		if req.GetName() != req.GetId() {
			badFields[globals.NameField] = "Target name provided but does not match the given ID value from the URL."
		}
		switch {
		case scopeIdEmpty && scopeNameEmpty:
			badFields[globals.ScopeIdField] = "Scope ID or scope name must be provided when target name is used."
			badFields["scope_name"] = "Scope ID or scope name must be provided when target name is used."
		case !scopeIdEmpty && !scopeNameEmpty:
			badFields[globals.ScopeIdField] = "Scope ID and scope name cannot both be provided when target name is used."
			badFields["scope_name"] = "Scope ID and scope name cannot both be provided when target name is used."
		}
	}
	if req.GetHostId() != "" {
		switch host.SubtypeFromId(req.GetHostId()) {
		case static.Subtype:
		default:
			badFields[globals.HostIdField] = "Incorrectly formatted identifier."
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
