package workers

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}
)

// Service handles request as described by the pbs.WorkerServiceServer interface.
type Service struct {
	pbs.UnimplementedWorkerServiceServer

	repoFn    common.ServersRepoFactory
	iamRepoFn common.IamRepoFactory
}

// NewService returns a worker service which handles worker related requests to boundary.
func NewService(ctx context.Context, repo common.ServersRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	const op = "workers.NewService"
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing servers repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	return Service{repoFn: repo, iamRepoFn: iamRepoFn}, nil
}

var _ pbs.WorkerServiceServer = Service{}

// ListWorkers implements the interface pbs.WorkerServiceServer.
func (s Service) ListWorkers(ctx context.Context, req *pbs.ListWorkersRequest) (*pbs.ListWorkersResponse, error) {
	if err := validateListRequest(req); err != nil {
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

	scopeIds, scopeInfoMap, err := scopeids.GetListingScopeIds(
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.Worker, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListWorkersResponse{}, nil
	}

	ul, err := s.listFromRepo(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	if len(ul) == 0 {
		return &pbs.ListWorkersResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Worker, 0, len(ul))
	res := perms.Resource{
		Type: resource.Worker,
	}
	for _, item := range ul {
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

		item, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListWorkersResponse{Items: finalItems}, nil
}

// GetWorker implements the interface pbs.WorkerServiceServer.
func (s Service) GetWorker(ctx context.Context, req *pbs.GetWorkerRequest) (*pbs.GetWorkerResponse, error) {
	const op = "workers.(Service).GetWorker"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	w, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, w.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, w, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetWorkerResponse{Item: item}, nil
}

// DeleteWorker implements the interface pbs.WorkerServiceServer.
func (s Service) DeleteWorker(ctx context.Context, req *pbs.DeleteWorkerRequest) (*pbs.DeleteWorkerResponse, error) {
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

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*servers.Worker, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	wl, err := repo.ListWorkers(ctx, scopeIds, servers.WithLiveness(-1))
	if err != nil {
		return nil, err
	}
	return wl, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*servers.Worker, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	w, err := repo.LookupWorker(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return nil, handlers.NotFoundErrorf("Worker %q doesn't exist.", id)
		}
		return nil, err
	}
	if w == nil {
		return nil, handlers.NotFoundErrorf("Worker %q doesn't exist.", id)
	}
	return w, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "workers.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteWorker(ctx, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete worker"))
	}
	return rows > 0, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Worker), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		w, err := repo.LookupWorker(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if w == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = w.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(ctx context.Context, in *servers.Worker, opt ...handlers.Option) (*pb.Worker, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building worker proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Worker{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
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
	if outputFields.Has(globals.AddressField) && in.GetAddress() != "" {
		out.Address = wrapperspb.String(in.GetAddress())
	}
	if outputFields.Has(globals.CanonicalAddressField) {
		out.CanonicalAddress = in.CanonicalAddress()
	}
	if outputFields.Has(globals.LastStatusTimeField) {
		out.LastStatusTime = in.GetLastStatusTime().GetTimestamp()
	}
	if outputFields.Has(globals.CanonicalTagsField) && len(in.CanonicalTags()) > 0 {
		var err error
		out.Tags, err = tagsToMapProto(in.CanonicalTags())
		if err != nil {
			return nil, err
		}
	}
	if outputFields.Has(globals.TagsField) && len(in.GetApiTags()) > 0 {
		var err error
		out.Tags, err = tagsToMapProto(in.GetApiTags())
		if err != nil {
			return nil, err
		}
	}
	if outputFields.Has(globals.ConfigurationField) {
		if in.GetWorkerReportedAddress() != "" ||
			in.GetWorkerReportedName() != "" ||
			len(in.GetConfigTags()) > 0 {
			out.WorkerConfig = &pb.WorkerConfig{}
		}
		if len(in.GetConfigTags()) > 0 {
			var err error
			out.GetWorkerConfig().Tags, err = tagsToMapProto(in.GetConfigTags())
			if err != nil {
				return nil, err
			}
		}
		out.GetWorkerConfig().Address = in.GetWorkerReportedAddress()
		out.GetWorkerConfig().Name = in.GetWorkerReportedName()
	}

	return &out, nil
}

func tagsToMapProto(in map[string][]string) (map[string]*structpb.ListValue, error) {
	b := make(map[string][]interface{})
	for k, v := range in {
		result := make([]interface{}, 0, len(v))
		for _, t := range v {
			result = append(result, t)
		}
		b[k] = result
	}
	ret := make(map[string]*structpb.ListValue)
	var err error
	for k, v := range b {
		ret[k], err = structpb.NewList(v)
		if err != nil {
			return nil, err
		}
	}
	return ret, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetWorkerRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, servers.WorkerPrefix)
}

func validateListRequest(req *pbs.ListWorkersRequest) error {
	badFields := map[string]string{}
	if req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Must be 'global' when listing."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateDeleteRequest(req *pbs.DeleteWorkerRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, servers.WorkerPrefix)
}
