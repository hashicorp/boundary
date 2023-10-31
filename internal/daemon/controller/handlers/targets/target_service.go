// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package targets

import (
	"context"
	stderrors "errors"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	wl "github.com/hashicorp/boundary/internal/daemon/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	intglobals "github.com/hashicorp/boundary/internal/globals"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/plugin"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/targets"
	fm "github.com/hashicorp/boundary/version"
	"github.com/hashicorp/go-bexpr"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	credentialDomain = "credential"
	hostDomain       = "host"
)

// extraWorkerFilterFunc takes in a set of workers and returns another set,
// after any filtering it wishes to perform. When calling one of these
// functions, the current set should be passed in and the returned set should be
// used if there is no error; it is up to the filter writer to ensure that what
// is returned, if no filtering is desired, is the input set.
//
// This is generally used to take in a set selected already from the database
// and possible filtered via target worker filters and provide additional
// filtering capabilities on those remaining workers.
type extraWorkerFilterFunc func(ctx context.Context, workers []*server.Worker, host, port string) ([]*server.Worker, error)

var (
	// ExtraWorkerFilters contains any custom worker filters that should be
	// layered in at session authorization time. These will be executed in-order
	// with the results from one fed into the next.
	ExtraWorkerFilters []extraWorkerFilterFunc

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.NewActionSet(
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.AddHostSources,
		action.SetHostSources,
		action.RemoveHostSources,
		action.AddCredentialSources,
		action.SetCredentialSources,
		action.RemoveCredentialSources,
		action.AuthorizeSession,
	)

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.NewActionSet(
		action.Create,
		action.List,
	)

	validateCredentialSourcesFn      = func(context.Context, globals.Subtype, []target.CredentialSource) error { return nil }
	ValidateIngressWorkerFilterFn    = IngressWorkerFilterUnsupported
	AuthorizeSessionWorkerFilterFn   = AuthorizeSessionWithWorkerFilter
	PostSessionAuthorizationCallback = DefaultPostSessionAuthorizationCallback
	WorkerFilterDeprecationMessage   = fmt.Sprintf("This field is deprecated. Use %s instead.", globals.EgressWorkerFilterField)
)

func IngressWorkerFilterUnsupported(string) error {
	return fmt.Errorf("Ingress Worker Filter field is not supported in OSS")
}

// Service handles request as described by the pbs.TargetServiceServer interface.
type Service struct {
	pbs.UnsafeTargetServiceServer

	repoFn                  target.RepositoryFactory
	iamRepoFn               common.IamRepoFactory
	serversRepoFn           common.ServersRepoFactory
	sessionRepoFn           session.RepositoryFactory
	pluginHostRepoFn        common.PluginHostRepoFactory
	staticHostRepoFn        common.StaticRepoFactory
	vaultCredRepoFn         common.VaultCredentialRepoFactory
	staticCredRepoFn        common.StaticCredentialRepoFactory
	downstreams             common.Downstreamers
	kmsCache                *kms.Kms
	workerStatusGracePeriod *atomic.Int64
	controllerExt           intglobals.ControllerExtension
}

var _ pbs.TargetServiceServer = (*Service)(nil)

// NewService returns a target service which handles target related requests to boundary.
func NewService(
	ctx context.Context,
	kmsCache *kms.Kms,
	repoFn target.RepositoryFactory,
	iamRepoFn common.IamRepoFactory,
	serversRepoFn common.ServersRepoFactory,
	sessionRepoFn session.RepositoryFactory,
	pluginHostRepoFn common.PluginHostRepoFactory,
	staticHostRepoFn common.StaticRepoFactory,
	vaultCredRepoFn common.VaultCredentialRepoFactory,
	staticCredRepoFn common.StaticCredentialRepoFactory,
	downstreams common.Downstreamers,
	workerStatusGracePeriod *atomic.Int64,
	controllerExt intglobals.ControllerExtension,
) (Service, error) {
	const op = "targets.NewService"
	if kmsCache == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing kms repo")
	}
	if repoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing target repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if serversRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing server repository")
	}
	if sessionRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing session repository")
	}
	if pluginHostRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing plugin host repository")
	}
	if staticHostRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing static host repository")
	}
	if vaultCredRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing vault credential repository")
	}
	if staticCredRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing static credential repository")
	}
	return Service{
		repoFn:                  repoFn,
		iamRepoFn:               iamRepoFn,
		serversRepoFn:           serversRepoFn,
		sessionRepoFn:           sessionRepoFn,
		pluginHostRepoFn:        pluginHostRepoFn,
		staticHostRepoFn:        staticHostRepoFn,
		vaultCredRepoFn:         vaultCredRepoFn,
		staticCredRepoFn:        staticCredRepoFn,
		downstreams:             downstreams,
		kmsCache:                kmsCache,
		workerStatusGracePeriod: workerStatusGracePeriod,
		controllerExt:           controllerExt,
	}, nil
}

// ListTargets implements the interface pbs.TargetServiceServer.
func (s Service) ListTargets(ctx context.Context, req *pbs.ListTargetsRequest) (*pbs.ListTargetsResponse, error) {
	const op = "targets.(Service).ListSessions"

	if err := validateListRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
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

	var err error
	var authzScopes map[string]*scopes.ScopeInfo
	if req.GetRecursive() {
		authzScopes, err = authResults.ScopesAuthorizedForList(ctx, req.GetScopeId(), resource.Target)
	} else {
		authzScopes = map[string]*scopes.ScopeInfo{authResults.Scope.Id: authResults.Scope}
	}
	if err != nil {
		return nil, err
	}

	// Get all user permissions for the requested scope(s).
	userPerms := authResults.ACL().ListPermissions(authzScopes, resource.Target, IdActions, authResults.UserId)
	if len(userPerms) == 0 {
		return &pbs.ListTargetsResponse{}, nil
	}

	tl, err := s.listFromRepo(ctx, userPerms)
	if err != nil {
		return nil, err
	}
	if len(tl) == 0 {
		return &pbs.ListTargetsResponse{}, nil
	}

	filter, err := handlers.NewFilter(ctx, req.GetFilter())
	if err != nil {
		return nil, err
	}

	finalItems := make([]*pb.Target, 0, len(tl))
	for _, item := range tl {
		pr := perms.Resource{Id: item.GetPublicId(), ScopeId: item.GetProjectId(), Type: resource.Target}
		outputFields := authResults.FetchOutputFields(pr, action.List).SelfOrDefaults(authResults.UserId)

		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))

		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authzScopes[item.GetProjectId()]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&pr)).Strings()
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}

		item, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, err
		}

		filterable, err := subtypes.Filterable(item)
		if err != nil {
			return nil, err
		}
		if filter.Match(filterable) {
			finalItems = append(finalItems, item)
		}
	}

	return &pbs.ListTargetsResponse{Items: finalItems}, nil
}

// GetTarget implements the interface pbs.TargetServiceServer.
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
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

// AddTargetHostSources implements the interface pbs.TargetServiceServer.
func (s Service) AddTargetHostSources(ctx context.Context, req *pbs.AddTargetHostSourcesRequest) (*pbs.AddTargetHostSourcesResponse, error) {
	const op = "targets.(Service).AddTargetHostSources"

	if err := validateAddHostSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddHostSources)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	t, err := s.addHostSourcesInRepo(ctx, req.GetId(), req.GetHostSourceIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	ts := t.GetHostSources()
	cl := t.GetCredentialSources()

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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
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
	authResults := s.authResult(ctx, req.GetId(), action.SetHostSources)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetTargetHostSourcesResponse{Item: item}, nil
}

// RemoveTargetHostSources implements the interface pbs.TargetServiceServer.
func (s Service) RemoveTargetHostSources(ctx context.Context, req *pbs.RemoveTargetHostSourcesRequest) (*pbs.RemoveTargetHostSourcesResponse, error) {
	const op = "targets.(Service).RemoveTargetHostSources"

	if err := validateRemoveHostSourcesRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveHostSources)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveTargetHostSourcesResponse{Item: item}, nil
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

	t, ts, cl, err := s.addCredentialSourcesInRepo(ctx, req.GetId(), req.GetBrokeredCredentialSourceIds(), req.GetInjectedApplicationCredentialSourceIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
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

	t, ts, cl, err := s.setCredentialSourcesInRepo(ctx, req.GetId(), req.GetBrokeredCredentialSourceIds(), req.GetInjectedApplicationCredentialSourceIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
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

	t, ts, cl, err := s.removeCredentialSourcesInRepo(ctx, req.GetId(), req.GetBrokeredCredentialSourceIds(), req.GetInjectedApplicationCredentialSourceIds(), req.GetVersion())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, t.GetPublicId(), IdActions).Strings()))
	}
	t.SetHostSources(ts)
	t.SetCredentialSources(cl)

	item, err := toProto(ctx, t, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.RemoveTargetCredentialSourcesResponse{Item: item}, nil
}

// If set, use the worker_filter or egress_worker_filter to filter the selected workers
// and ensure we have workers available to service this request. The second return
// argument is always nil.
func AuthorizeSessionWithWorkerFilter(
	_ context.Context,
	t target.Target,
	selectedWorkers wl.WorkerList,
	_ string,
	_ intglobals.ControllerExtension,
	_ common.Downstreamers,
	_ ...target.Option,
) (wl.WorkerList, *server.Worker, error) {
	if len(selectedWorkers) > 0 {
		var eval *bexpr.Evaluator
		var err error
		switch {
		case len(t.GetEgressWorkerFilter()) > 0:
			eval, err = bexpr.CreateEvaluator(t.GetEgressWorkerFilter())
		case len(t.GetWorkerFilter()) > 0:
			eval, err = bexpr.CreateEvaluator(t.GetWorkerFilter())
		default: // No filter
			return selectedWorkers, nil, nil
		}
		if err != nil {
			return nil, nil, err
		}

		selectedWorkers, err = selectedWorkers.Filtered(eval)
		if err != nil {
			return nil, nil, err
		}
	}

	if len(selectedWorkers) == 0 {
		return nil, nil, handlers.ApiErrorWithCodeAndMessage(
			codes.FailedPrecondition,
			"No workers are available to handle this session, or all have been filtered.")
	}

	return selectedWorkers, nil, nil
}

func DefaultPostSessionAuthorizationCallback(context.Context, intglobals.ControllerExtension, *kms.Kms, *target.Repository, target.Target, *session.Session, *server.Worker) error {
	return nil
}

func (s Service) AuthorizeSession(ctx context.Context, req *pbs.AuthorizeSessionRequest) (_ *pbs.AuthorizeSessionResponse, retErr error) {
	const op = "targets.(Service).AuthorizeSession"
	if err := validateAuthorizeSessionRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AuthorizeSession,
		target.WithName(req.GetName()),
		target.WithProjectId(req.GetScopeId()),
		target.WithProjectName(req.GetScopeName()),
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

	if t.GetDefaultPort() == 0 {
		return nil, handlers.ConflictErrorf("Target does not have default port defined.")
	}

	// Get the target information
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	t, err = repo.LookupTarget(ctx, t.GetPublicId())
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, handlers.NotFoundErrorf("Target %q not found.", t.GetPublicId())
		}
		return nil, err
	}
	if t == nil {
		return nil, handlers.NotFoundErrorf("Target %q not found.", t.GetPublicId())
	}
	hostSources := t.GetHostSources()
	credSources := t.GetCredentialSources()
	if len(credSources) > 0 {
		if err := validateCredentialSourcesFn(ctx, t.GetType(), credSources); err != nil {
			return nil, err
		}
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

	p := strconv.FormatUint(uint64(t.GetDefaultPort()), 10)
	var h, hostId, hostSetId string

	switch {
	case t.GetAddress() != "":
		h = t.GetAddress()

	default:
		requestedId := req.GetHostId()
		staticHostRepo, err := s.staticHostRepoFn()
		if err != nil {
			return nil, err
		}
		pluginHostRepo, err := s.pluginHostRepoFn()
		if err != nil {
			return nil, err
		}

		var pluginHostSetIds []string
		var endpoints []*host.Endpoint
		for _, hSource := range hostSources {
			hsId := hSource.Id()
			switch globals.ResourceInfoFromPrefix(hsId).Subtype {
			case static.Subtype:
				eps, err := staticHostRepo.Endpoints(ctx, hsId)
				if err != nil {
					return nil, err
				}
				endpoints = append(endpoints, eps...)
			default:
				// Batch the plugin host set ids since each round trip to the plugin
				// has the potential to be expensive.
				pluginHostSetIds = append(pluginHostSetIds, hsId)
			}
		}
		if len(pluginHostSetIds) > 0 {
			eps, err := pluginHostRepo.Endpoints(ctx, pluginHostSetIds)
			if err != nil {
				return nil, err
			}
			endpoints = append(endpoints, eps...)
		}

		if len(endpoints) == 0 {
			return nil, handlers.NotFoundErrorf("No host sources or address found for given target.")
		}

		var chosenEndpoint *host.Endpoint
		if requestedId != "" {
			for _, ep := range endpoints {
				if ep.HostId == requestedId {
					chosenEndpoint = ep
				}
			}
			if chosenEndpoint == nil {
				// We didn't find it
				return nil, handlers.InvalidArgumentErrorf(
					"Errors in provided fields.",
					map[string]string{
						"host_id": "The requested host id is not available.",
					})
			}
		}

		if chosenEndpoint == nil {
			chosenEndpoint = endpoints[rand.Intn(len(endpoints))]
		}

		hostId = chosenEndpoint.HostId
		hostSetId = chosenEndpoint.SetId
		h = chosenEndpoint.Address
	}

	if h == "" {
		return nil, handlers.ApiErrorWithCodeAndMessage(
			codes.FailedPrecondition,
			"No host was discovered after checking target address and host sources.")
	}

	// Ensure we don't have a port from the address, which would be unexpected
	// FIXME: We've decided to hold off on making this an error until 0.14. In
	// the meantime, ignore any port coming from the host address.
	hostWithoutPort, _, err := net.SplitHostPort(h)
	switch {
	case err != nil && strings.Contains(err.Error(), globals.MissingPortErrStr):
		// This is what we expect
	case err != nil:
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error when parsing the chosen endpoint host address"))
	case err == nil:
		h = hostWithoutPort
		// Use below logic for 0.14:
		/*
			return nil, handlers.ApiErrorWithCodeAndMessage(
				codes.FailedPrecondition,
				"Address specified for use unexpectedly contains a port.")
		*/
	}

	// Generate the endpoint URL
	endpointUrl := &url.URL{
		Scheme: t.GetType().String(),
		Host:   net.JoinHostPort(h, p),
	}

	// Get workers and filter down to ones that can service this request
	selectedWorkers, err := serversRepo.ListWorkers(ctx, []string{scope.Global.String()}, server.WithLiveness(time.Duration(s.workerStatusGracePeriod.Load())))
	if err != nil {
		return nil, err
	}

	if len(selectedWorkers) == 0 {
		return nil, handlers.ApiErrorWithCodeAndMessage(
			codes.FailedPrecondition,
			"No workers are available to handle this session.")
	}

	selectedWorkers, protoWorker, err := AuthorizeSessionWorkerFilterFn(ctx, t, selectedWorkers, h, s.controllerExt, s.downstreams)
	if err != nil {
		return nil, err
	}

	// Randomize the workers
	rand.Shuffle(len(selectedWorkers), func(i, j int) {
		selectedWorkers[i], selectedWorkers[j] = selectedWorkers[j], selectedWorkers[i]
	})

	var vaultReqs []credential.Request
	var staticIds []string
	var dynCreds []*session.DynamicCredential
	var staticCreds []*session.StaticCredential
	for _, cs := range credSources {
		switch cs.Type() {
		case target.LibraryCredentialSourceType:
			vaultReqs = append(vaultReqs, credential.Request{
				SourceId: cs.Id(),
				Purpose:  cs.CredentialPurpose(),
			})
			dynCreds = append(dynCreds, session.NewDynamicCredential(cs.Id(), cs.CredentialPurpose()))
		case target.StaticCredentialSourceType:
			staticIds = append(staticIds, cs.Id())
			staticCreds = append(staticCreds, session.NewStaticCredential(cs.Id(), cs.CredentialPurpose()))
		}
	}

	expTime := timestamppb.Now()
	expTime.Seconds += int64(t.GetSessionMaxSeconds())
	sessionComposition := session.ComposedOf{
		UserId:              authResults.UserId,
		HostId:              hostId,
		TargetId:            t.GetPublicId(),
		HostSetId:           hostSetId,
		AuthTokenId:         authResults.AuthTokenId,
		ProjectId:           authResults.Scope.Id,
		Endpoint:            endpointUrl.String(),
		ExpirationTime:      &timestamp.Timestamp{Timestamp: expTime},
		ConnectionLimit:     t.GetSessionConnectionLimit(),
		WorkerFilter:        t.GetWorkerFilter(),
		EgressWorkerFilter:  t.GetEgressWorkerFilter(),
		IngressWorkerFilter: t.GetIngressWorkerFilter(),
		DynamicCredentials:  dynCreds,
		StaticCredentials:   staticCreds,
	}
	if protoWorker != nil {
		sessionComposition.ProtocolWorkerId = protoWorker.GetPublicId()
	}
	sess, err := session.New(ctx, sessionComposition)
	if err != nil {
		return nil, err
	}
	wrapper, err := s.kmsCache.GetWrapper(ctx, authResults.Scope.Id, kms.KeyPurposeSessions)
	if err != nil {
		return nil, err
	}
	sess, err = sessionRepo.CreateSession(ctx, wrapper, sess, wl.WorkerList(selectedWorkers).Addresses())
	if err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			// Delete created session in case of errors.
			// Use new context for deletion in case error is because of context cancellation.
			deleteCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := sessionRepo.DeleteSession(deleteCtx, sess.PublicId)
			retErr = stderrors.Join(retErr, err)
		}
	}()

	subtype := target.SubtypeFromId(t.GetPublicId())
	subtypeEntry, err := subtypeRegistry.get(subtype)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if err := subtypeEntry.validateSessionStateFunc(ctx, sess); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var dynamic []credential.Dynamic
	var staticCredsById map[string]credential.Static
	if len(vaultReqs) > 0 {
		credRepo, err := s.vaultCredRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		dynamic, err = credRepo.Issue(ctx, sess.GetPublicId(), vaultReqs, credential.WithTemplateData(authResults.UserData))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		defer func() {
			if retErr != nil {
				// Revoke issued credentials in case of errors.
				// Use new context for deletion in case error is because of context cancellation.
				deleteCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
				defer cancel()
				err := credRepo.Revoke(deleteCtx, sess.PublicId)
				retErr = stderrors.Join(retErr, err)
				// This leaves the credential in a state which will allow it to be cleaned up
				// by the periodic credential cleanup job.
			}
		}()
	}

	if len(staticIds) > 0 {
		credRepo, err := s.staticCredRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		// Remove duplicate requests
		staticIds = strutil.RemoveDuplicates(staticIds, false)
		creds, err := credRepo.Retrieve(ctx, t.GetProjectId(), staticIds)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		staticCredsById = make(map[string]credential.Static)
		for _, c := range creds {
			staticCredsById[c.GetPublicId()] = c
		}
	}

	var creds []*pb.SessionCredential
	var workerCreds []session.Credential
	for _, cred := range dynamic {
		switch cred.Purpose() {
		case credential.InjectedApplicationPurpose:
			c, err := dynamicToWorkerCredential(ctx, cred)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			workerCreds = append(workerCreds, c)

		case credential.BrokeredPurpose:
			c, err := dynamicToSessionCredential(ctx, cred)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			creds = append(creds, c)

		default:
			return nil, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unsupported credential purpose %s", cred.Purpose()))
		}
	}

	for _, sc := range staticCreds {
		switch sc.CredentialPurpose {
		case string(credential.InjectedApplicationPurpose):
			c, err := staticToWorkerCredential(ctx, staticCredsById[sc.CredentialStaticId])
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			workerCreds = append(workerCreds, c)

		case string(credential.BrokeredPurpose):
			c, err := staticToSessionCredential(ctx, staticCredsById[sc.CredentialStaticId])
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			creds = append(creds, c)

		default:
			return nil, errors.New(ctx, errors.Unknown, op, fmt.Sprintf("unsupported credential purpose %s", sc.CredentialPurpose))
		}
	}

	if len(workerCreds) > 0 {
		// store credentials in repo, worker will request creds when a connection is established
		// These credentials are deleted with the session, so nothing extra to cleanup in case of errors.
		err = sessionRepo.AddSessionCredentials(ctx, sess.ProjectId, sess.PublicId, workerCreds)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	// this is an edge case issue where the hostId cannot be empty when trying to execute an ssh connection
	// on a tcp target type. By setting the hostId to the targetId value, this will enable support of previous
	// boundary cli versions.
	if fm.SupportsFeature(fm.Binary, fm.UseTargetIdForHostId) && t.GetAddress() != "" {
		hostId = t.GetPublicId()
	}

	sad := &pb.SessionAuthorizationData{
		SessionId:         sess.PublicId,
		TargetId:          t.GetPublicId(),
		Scope:             authResults.Scope,
		CreatedTime:       sess.CreateTime.GetTimestamp(),
		Expiration:        sess.ExpirationTime.GetTimestamp(),
		EndpointPort:      t.GetDefaultPort(),
		Type:              t.GetType().String(),
		Certificate:       sess.Certificate,
		PrivateKey:        sess.CertificatePrivateKey,
		HostId:            hostId,
		Endpoint:          endpointUrl.String(),
		WorkerInfo:        wl.WorkerList(selectedWorkers).WorkerInfos(),
		ConnectionLimit:   t.GetSessionConnectionLimit(),
		DefaultClientPort: t.GetDefaultClientPort(),
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
		Expiration:         sess.ExpirationTime.GetTimestamp(),
		EndpointPort:       t.GetDefaultPort(),
		Type:               t.GetType().String(),
		AuthorizationToken: encodedMarshaledSad,
		UserId:             authResults.UserId,
		HostId:             hostId,
		HostSetId:          hostSetId,
		Endpoint:           endpointUrl.String(),
		Credentials:        creds,
	}

	if err := PostSessionAuthorizationCallback(
		ctx,
		s.controllerExt,
		s.kmsCache,
		repo,
		t,
		sess,
		protoWorker,
	); err != nil {
		// Errors here will automatically delete the session and associated resources
		// using deferred statements above.
		return nil, errors.Wrap(ctx, err, op)
	}

	return &pbs.AuthorizeSessionResponse{Item: ret}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	u, err := repo.LookupTarget(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil, nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
		}
		return nil, nil, nil, err
	}
	hs := u.GetHostSources()
	cl := u.GetCredentialSources()

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
	if item.GetEgressWorkerFilter() != nil {
		opts = append(opts, target.WithEgressWorkerFilter(item.GetEgressWorkerFilter().GetValue()))
	}
	if item.GetIngressWorkerFilter() != nil {
		opts = append(opts, target.WithIngressWorkerFilter(item.GetIngressWorkerFilter().GetValue()))
	}
	if item.GetAddress() != nil {
		opts = append(opts, target.WithAddress(strings.TrimSpace(item.GetAddress().GetValue())))
	}

	attr, err := subtypeRegistry.newAttribute(target.SubtypeFromType(item.GetType()), item.GetAttrs())
	if err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, err.Error())
	}
	opts = append(opts, attr.Options()...)

	u, err := target.New(ctx, target.SubtypeFromType(item.GetType()), item.GetScopeId(), opts...)
	if err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build target for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, err := repo.CreateTarget(ctx, u)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create target"))
	}
	hs := out.GetHostSources()
	cl := out.GetCredentialSources()

	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create target but no error returned from repository.")
	}
	return out, hs, cl, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Target) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).updateInRepo"
	var dbMask []string
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
	// worker_filter is deprecated, but we allow users who have migrated with a worker_filter value to update it.
	if workerFilter := item.GetWorkerFilter(); workerFilter != nil {
		opts = append(opts, target.WithWorkerFilter(item.GetWorkerFilter().GetValue()))
	}
	if egressFilter := item.GetEgressWorkerFilter(); egressFilter != nil {
		opts = append(opts, target.WithEgressWorkerFilter(item.GetEgressWorkerFilter().GetValue()))
	}
	if ingressFilter := item.GetIngressWorkerFilter(); ingressFilter != nil {
		opts = append(opts, target.WithIngressWorkerFilter(item.GetIngressWorkerFilter().GetValue()))
	}
	if item.GetAddress() != nil {
		dbMask = append(dbMask, "Address")
		opts = append(opts, target.WithAddress(strings.TrimSpace(item.GetAddress().GetValue())))
	}
	subtype := target.SubtypeFromId(id)

	attr, err := subtypeRegistry.newAttribute(subtype, item.GetAttrs())
	if err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, err.Error())
	}

	opts = append(opts, attr.Options()...)

	version := item.GetVersion()

	u, err := target.New(ctx, subtype, scopeId, opts...)
	if err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build target for update: %v.", err)
	}
	if err := u.SetPublicId(ctx, id); err != nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set target id: %v.", err)
	}

	maskManager, err := subtypeRegistry.maskManager(subtype)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target"))
	}
	dbMask = append(dbMask, maskManager.Translate(mask)...)
	if len(dbMask) == 0 {
		return nil, nil, nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	out, rowsUpdated, err := repo.UpdateTarget(ctx, u, version, dbMask, opts...)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update target"))
	}
	hs := out.GetHostSources()
	cl := out.GetCredentialSources()

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

func (s Service) listFromRepo(ctx context.Context, perms []perms.Permission) ([]target.Target, error) {
	repo, err := s.repoFn(target.WithPermissions(perms))
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListTargets(ctx, target.WithLimit(-1))
	if err != nil {
		return nil, err
	}
	return ul, nil
}

func (s Service) addHostSourcesInRepo(ctx context.Context, targetId string, hostSourceIds []string, version uint32) (target.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.AddTargetHostSources(ctx, targetId, version, strutil.RemoveDuplicates(hostSourceIds, false))
	if err != nil {
		var internalErr *errors.Err
		if stderrors.As(err, &internalErr) && internalErr.Code == errors.Conflict {
			// The conflict error is surfaced directly as it's correctly
			// converted all the way down to the HTTP status.
			return nil, err
		}
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Failed to add target host sources")
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after adding host sources to it.")
	}
	return out, nil
}

func (s Service) setHostSourcesInRepo(ctx context.Context, targetId string, hostSourceIds []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).setSourcesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}
	_, _, _, err = repo.SetTargetHostSources(ctx, targetId, version, strutil.RemoveDuplicates(hostSourceIds, false))
	if err != nil {
		var internalErr *errors.Err
		if stderrors.As(err, &internalErr) && internalErr.Code == errors.Conflict {
			// The conflict error is surfaced directly as it's correctly
			// converted all the way down to the HTTP status.
			return nil, nil, nil, err
		}
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Failed to set target host sources")
	}

	out, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after setting host sources"))
	}
	hs := out.GetHostSources()
	cl := out.GetCredentialSources()

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
	out, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after removing host sources"))
	}
	hs := out.GetHostSources()
	cl := out.GetCredentialSources()

	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after removing host sources from it.")
	}
	return out, hs, cl, nil
}

func (s Service) addCredentialSourcesInRepo(ctx context.Context, targetId string, brokeredIds []string, injectedAppIds []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}

	var creds target.CredentialSources
	if len(brokeredIds) > 0 {
		creds.BrokeredCredentialIds = strutil.RemoveDuplicates(brokeredIds, false)
	}
	if len(injectedAppIds) > 0 {
		creds.InjectedApplicationCredentialIds = strutil.RemoveDuplicates(injectedAppIds, false)
	}

	out, err := repo.AddTargetCredentialSources(ctx, targetId, version, creds)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add credential sources to target: %v.", err)
	}
	hs := out.GetHostSources()
	credSources := out.GetCredentialSources()

	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after adding credential sources to it.")
	}
	return out, hs, credSources, nil
}

func (s Service) setCredentialSourcesInRepo(ctx context.Context, targetId string, brokeredIds []string, injectedAppIds []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).setCredentialSourcesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}

	var ids target.CredentialSources
	if len(brokeredIds) > 0 {
		ids.BrokeredCredentialIds = strutil.RemoveDuplicates(brokeredIds, false)
	}
	if len(injectedAppIds) > 0 {
		ids.InjectedApplicationCredentialIds = strutil.RemoveDuplicates(injectedAppIds, false)
	}

	_, _, _, err = repo.SetTargetCredentialSources(ctx, targetId, version, ids)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set credential sources in target: %v.", err)
	}

	out, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after setting credential sources"))
	}
	hs := out.GetHostSources()
	credSources := out.GetCredentialSources()

	if out == nil {
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup target after setting credential sources for it.")
	}
	return out, hs, credSources, nil
}

func (s Service) removeCredentialSourcesInRepo(ctx context.Context, targetId string, brokeredIds []string, injectedAppIds []string, version uint32) (target.Target, []target.HostSource, []target.CredentialSource, error) {
	const op = "targets.(Service).removeCredentialSourcesInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, nil, nil, err
	}

	var ids target.CredentialSources
	if len(brokeredIds) > 0 {
		ids.BrokeredCredentialIds = strutil.RemoveDuplicates(brokeredIds, false)
	}
	if len(injectedAppIds) > 0 {
		ids.InjectedApplicationCredentialIds = strutil.RemoveDuplicates(injectedAppIds, false)
	}
	_, err = repo.DeleteTargetCredentialSources(ctx, targetId, version, ids)
	if err != nil {
		// TODO: Figure out a way to surface more helpful error info beyond the Internal error.
		return nil, nil, nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove credential sources from target: %v.", err)
	}
	out, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, nil, nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up target after removing credential sources"))
	}
	hs := out.GetHostSources()
	credSources := out.GetCredentialSources()

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
		t, err = repo.LookupTarget(ctx, id, lookupOpt...)
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
		parentId = t.GetProjectId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	ret := auth.Verify(ctx, opts...)
	ret.RoundTripValue = t
	return ret
}

func toProto(ctx context.Context, in target.Target, opt ...handlers.Option) (*pb.Target, error) {
	const op = "target_service.toProto"
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building target proto")
	}
	outputFields := *opts.WithOutputFields
	hostSources := in.GetHostSources()
	credSources := in.GetCredentialSources()

	out := pb.Target{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetProjectId()
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = in.GetType().String()
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
	if outputFields.Has(globals.EgressWorkerFilterField) && in.GetEgressWorkerFilter() != "" {
		out.EgressWorkerFilter = wrapperspb.String(in.GetEgressWorkerFilter())
	}
	if outputFields.Has(globals.IngressWorkerFilterField) && in.GetIngressWorkerFilter() != "" {
		out.IngressWorkerFilter = wrapperspb.String(in.GetIngressWorkerFilter())
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
	}
	if outputFields.Has(globals.HostSourceIdsField) {
		for _, hs := range hostSources {
			out.HostSourceIds = append(out.HostSourceIds, hs.Id())
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
	if outputFields.Has(globals.AddressField) {
		out.Address = wrapperspb.String(in.GetAddress())
	}

	var brokeredSources, injectedAppSources []*pb.CredentialSource
	var brokeredSourceIds, injectedAppSourceIds []string

	for _, cs := range credSources {
		switch cs.CredentialPurpose() {
		case credential.BrokeredPurpose:
			brokeredSourceIds = append(brokeredSourceIds, cs.Id())
			brokeredSources = append(brokeredSources, &pb.CredentialSource{
				Id:                cs.Id(),
				CredentialStoreId: cs.CredentialStoreId(),
			})

		case credential.InjectedApplicationPurpose:
			injectedAppSources = append(injectedAppSources, &pb.CredentialSource{
				Id:                cs.Id(),
				CredentialStoreId: cs.CredentialStoreId(),
			})
			injectedAppSourceIds = append(injectedAppSourceIds, cs.Id())

		default:
			return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unrecognized purpose %q for credential source on target", cs.CredentialPurpose()))
		}
	}

	if outputFields.Has(globals.BrokeredCredentialSourceIdsField) {
		out.BrokeredCredentialSourceIds = brokeredSourceIds
	}
	if outputFields.Has(globals.BrokeredCredentialSourcesField) {
		out.BrokeredCredentialSources = brokeredSources
	}
	if outputFields.Has(globals.InjectedApplicationCredentialSourceIdsField) {
		out.InjectedApplicationCredentialSourceIds = injectedAppSourceIds
	}
	if outputFields.Has(globals.InjectedApplicationCredentialSourcesField) {
		out.InjectedApplicationCredentialSources = injectedAppSources
	}
	if outputFields.Has(globals.AttributesField) {
		if err := subtypeRegistry.setAttributes(in.GetType(), in, &out); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetTargetRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, target.Prefixes()...)
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
		if req.GetItem().GetType() == "" {
			badFields[globals.TypeField] = "This is a required field."
		} else if target.SubtypeFromType(req.GetItem().GetType()) == "" {
			badFields[globals.TypeField] = "Unknown type provided."
		}
		if workerFilter := req.GetItem().GetWorkerFilter(); workerFilter != nil {
			badFields[globals.WorkerFilterField] = WorkerFilterDeprecationMessage
		}
		if egressFilter := req.GetItem().GetEgressWorkerFilter(); egressFilter != nil {
			if _, err := bexpr.CreateEvaluator(egressFilter.GetValue()); err != nil {
				badFields[globals.EgressWorkerFilterField] = "Unable to successfully parse egress filter expression."
			}
		}
		if ingressFilter := req.GetItem().GetIngressWorkerFilter(); ingressFilter != nil {
			err := ValidateIngressWorkerFilterFn(ingressFilter.GetValue())
			if err != nil {
				badFields[globals.IngressWorkerFilterField] = err.Error()
			}
		}
		if address := req.GetItem().GetAddress(); address != nil {
			if len(address.GetValue()) < static.MinHostAddressLength ||
				len(address.GetValue()) > static.MaxHostAddressLength {
				badFields[globals.AddressField] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
			}
			_, _, err := net.SplitHostPort(address.GetValue())
			switch {
			case err == nil:
				badFields[globals.AddressField] = "Address does not support a port."
			case strings.Contains(err.Error(), globals.MissingPortErrStr):
			default:
				badFields[globals.AddressField] = fmt.Sprintf("Error parsing address: %v.", err)
			}
		}
		subtype := target.SubtypeFromType(req.GetItem().GetType())
		_, err := subtypeRegistry.get(subtype)
		if err != nil {
			badFields[globals.TypeField] = "Unknown type provided."
		} else {
			a, err := subtypeRegistry.newAttribute(subtype, req.GetItem().GetAttrs())
			if err != nil {
				badFields[globals.AttributesField] = "Attribute fields do not match the expected format."
			} else {
				for k, v := range a.Vet() {
					badFields[k] = v
				}
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateTargetRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		paths := req.GetUpdateMask().GetPaths()
		if handlers.MaskContains(paths, globals.NameField) && req.GetItem().GetName().GetValue() == "" {
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
		// worker_filter is mutually exclusive from ingress and egress filter
		workerFilterFound := false
		if workerFilter := req.GetItem().GetWorkerFilter(); workerFilter != nil {
			if _, err := bexpr.CreateEvaluator(workerFilter.GetValue()); err != nil {
				badFields[globals.WorkerFilterField] = "Unable to successfully parse filter expression."
			}
			workerFilterFound = true
		}
		if egressFilter := req.GetItem().GetEgressWorkerFilter(); egressFilter != nil {
			if workerFilterFound {
				badFields[globals.EgressWorkerFilterField] = fmt.Sprintf("Cannot set %s and %s; they are mutually exclusive fields.", globals.WorkerFilterField, globals.EgressWorkerFilterField)
			}
			if _, err := bexpr.CreateEvaluator(egressFilter.GetValue()); err != nil {
				badFields[globals.EgressWorkerFilterField] = "Unable to successfully parse egress filter expression."
			}
		}
		if ingressFilter := req.GetItem().GetIngressWorkerFilter(); ingressFilter != nil {
			if workerFilterFound {
				badFields[globals.IngressWorkerFilterField] = fmt.Sprintf("Cannot set %s and %s; they are mutually exclusive fields.", globals.WorkerFilterField, globals.IngressWorkerFilterField)
			}
			err := ValidateIngressWorkerFilterFn(ingressFilter.GetValue())
			if err != nil {
				badFields[globals.IngressWorkerFilterField] = err.Error()
			}
		}
		if address := req.GetItem().GetAddress(); address != nil {
			if len(address.GetValue()) < static.MinHostAddressLength ||
				len(address.GetValue()) > static.MaxHostAddressLength {
				badFields[globals.AddressField] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
			}
			_, _, err := net.SplitHostPort(address.GetValue())
			switch {
			case err == nil:
				badFields[globals.AddressField] = "Address does not support a port."
			case strings.Contains(err.Error(), globals.MissingPortErrStr):
			default:
				badFields[globals.AddressField] = fmt.Sprintf("Error parsing address: %v.", err)
			}
		}
		subtype := target.SubtypeFromId(req.GetId())
		_, err := subtypeRegistry.get(subtype)
		if err != nil {
			badFields[globals.TypeField] = "Unknown type provided."
		} else {
			if req.GetItem().GetType() != "" && target.SubtypeFromType(req.GetItem().GetType()) != subtype {
				badFields[globals.TypeField] = "Cannot modify the resource type."
			}

			a, err := subtypeRegistry.newAttribute(subtype, req.GetItem().GetAttrs())
			if err != nil {
				badFields[globals.AttributesField] = "Attribute fields do not match the expected format."
			} else {
				for k, v := range a.VetForUpdate(paths) {
					badFields[k] = v
				}
			}
		}
		return badFields
	}, target.Prefixes()...)
}

func validateDeleteRequest(req *pbs.DeleteTargetRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, target.Prefixes()...)
}

func validateListRequest(ctx context.Context, req *pbs.ListTargetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		!req.GetRecursive() {
		badFields[globals.ScopeIdField] = "This field must be a valid project scope ID or the list operation must be recursive."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddHostSourcesRequest(req *pbs.AddTargetHostSourcesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), target.Prefixes()...) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostSourceIds()) == 0 {
		badFields[globals.HostSourceIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostSourceIds() {
		if !handlers.ValidId(handlers.Id(id), globals.StaticHostSetPrefix, globals.PluginHostSetPrefix, globals.PluginHostSetPreviousPrefix) {
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
	if !handlers.ValidId(handlers.Id(req.GetId()), target.Prefixes()...) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for _, id := range req.GetHostSourceIds() {
		if !handlers.ValidId(handlers.Id(id), globals.StaticHostSetPrefix, globals.PluginHostSetPrefix, globals.PluginHostSetPreviousPrefix) {
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
	if !handlers.ValidId(handlers.Id(req.GetId()), target.Prefixes()...) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetHostSourceIds()) == 0 {
		badFields[globals.HostSourceIdsField] = "Must be non-empty."
	}
	for _, id := range req.GetHostSourceIds() {
		if !handlers.ValidId(handlers.Id(id), globals.StaticHostSetPrefix, globals.PluginHostSetPrefix, globals.PluginHostSetPreviousPrefix) {
			badFields[globals.HostSourceIdsField] = fmt.Sprintf("Incorrectly formatted host source identifier %q.", id)
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
	if !handlers.ValidId(handlers.Id(req.GetId()), target.Prefixes()...) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetBrokeredCredentialSourceIds())+len(req.GetInjectedApplicationCredentialSourceIds()) == 0 {
		badFields[globals.BrokeredCredentialSourceIdsField] = "Brokered or Injected Application Credential Source IDs must be provided."
		badFields[globals.InjectedApplicationCredentialSourceIdsField] = "Brokered or Injected Application Credential Source IDs must be provided."
	}
	for _, cl := range req.GetBrokeredCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl),
			globals.VaultCredentialLibraryPrefix,
			globals.UsernamePasswordCredentialPrefix,
			globals.UsernamePasswordCredentialPreviousPrefix,
			globals.SshPrivateKeyCredentialPrefix,
			globals.JsonCredentialPrefix) {
			badFields[globals.BrokeredCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
			break
		}
	}
	for _, cl := range req.GetInjectedApplicationCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl),
			globals.VaultCredentialLibraryPrefix,
			globals.VaultSshCertificateCredentialLibraryPrefix,
			globals.UsernamePasswordCredentialPrefix,
			globals.UsernamePasswordCredentialPreviousPrefix,
			globals.SshPrivateKeyCredentialPrefix) {
			badFields[globals.InjectedApplicationCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
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
	if !handlers.ValidId(handlers.Id(req.GetId()), target.Prefixes()...) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for _, cl := range req.GetBrokeredCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl),
			globals.VaultCredentialLibraryPrefix,
			globals.UsernamePasswordCredentialPrefix,
			globals.UsernamePasswordCredentialPreviousPrefix,
			globals.SshPrivateKeyCredentialPrefix,
			globals.JsonCredentialPrefix) {
			badFields[globals.BrokeredCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
			break
		}
	}
	for _, cl := range req.GetInjectedApplicationCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl),
			globals.VaultCredentialLibraryPrefix,
			globals.VaultSshCertificateCredentialLibraryPrefix,
			globals.UsernamePasswordCredentialPrefix,
			globals.UsernamePasswordCredentialPreviousPrefix,
			globals.SshPrivateKeyCredentialPrefix) {
			badFields[globals.InjectedApplicationCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
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
	if !handlers.ValidId(handlers.Id(req.GetId()), target.Prefixes()...) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if len(req.GetBrokeredCredentialSourceIds())+len(req.GetInjectedApplicationCredentialSourceIds()) == 0 {
		badFields[globals.BrokeredCredentialSourceIdsField] = "Brokered or Injected Application Credential Source IDs must be provided."
		badFields[globals.InjectedApplicationCredentialSourceIdsField] = "Brokered or Injected Application Credential Source IDs must be provided."
	}
	for _, cl := range req.GetBrokeredCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl),
			globals.VaultCredentialLibraryPrefix,
			globals.UsernamePasswordCredentialPrefix,
			globals.UsernamePasswordCredentialPreviousPrefix,
			globals.SshPrivateKeyCredentialPrefix,
			globals.JsonCredentialPrefix) {
			badFields[globals.BrokeredCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
			break
		}
	}
	for _, cl := range req.GetInjectedApplicationCredentialSourceIds() {
		if !handlers.ValidId(handlers.Id(cl),
			globals.VaultCredentialLibraryPrefix,
			globals.VaultSshCertificateCredentialLibraryPrefix,
			globals.UsernamePasswordCredentialPrefix,
			globals.UsernamePasswordCredentialPreviousPrefix,
			globals.SshPrivateKeyCredentialPrefix,
			globals.JsonCredentialPrefix) {
			badFields[globals.InjectedApplicationCredentialSourceIdsField] = fmt.Sprintf("Incorrectly formatted credential source identifier %q.", cl)
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
		if !handlers.ValidId(handlers.Id(req.GetId()), target.Prefixes()...) {
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
		switch globals.ResourceInfoFromPrefix(req.GetHostId()).Subtype {
		case static.Subtype, plugin.Subtype:
		default:
			badFields[globals.HostIdField] = "Incorrectly formatted identifier."
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
