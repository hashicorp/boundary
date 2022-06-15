package workers

import (
	"context"
	"fmt"
	"strings"

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
	"github.com/hashicorp/boundary/internal/servers/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/workers"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/hashicorp/nodeenrollment/types"
	"github.com/mr-tron/base58"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	PkiWorkerType = "pki"
	KmsWorkerType = "kms"
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
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.CreateWorkerLed,
		action.List,
	}
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.Worker{}}, handlers.MaskSource{&pb.Worker{}}); err != nil {
		panic(err)
	}
}

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

// CreateWorker implements the interface pbs.WorkerServiceServer.
func (s Service) CreateWorkerLed(ctx context.Context, req *pbs.CreateWorkerLedRequest) (*pbs.CreateWorkerLedResponse, error) {
	const op = "workers.(Service).CreateWorkerLed"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.CreateWorkerLed)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	reqBytes, err := base58.FastBase58Decoding(req.GetItem().WorkerGeneratedAuthToken.GetValue())
	if err != nil {
		return nil, fmt.Errorf("%s: error decoding node_credentials_token: %w", op, err)
	}
	// Decode the proto into the request
	creds := new(types.FetchNodeCredentialsRequest)
	if err := proto.Unmarshal(reqBytes, creds); err != nil {
		return nil, fmt.Errorf("%s: error unmarshaling node_credentials_token: %w", op, err)
	}
	created, err := s.createInRepo(ctx, req.GetItem(), creds)
	if err != nil {
		return nil, fmt.Errorf("%s: error creating worker: %w", op, err)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, created.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, created, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateWorkerLedResponse{Item: item}, nil
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

// UpdateWorker implements the interface pbs.WorkerServiceServer.
func (s Service) UpdateWorker(ctx context.Context, req *pbs.UpdateWorkerRequest) (*pbs.UpdateWorkerResponse, error) {
	const op = "workers.(Service).UpdateWorker"

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	w, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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

	return &pbs.UpdateWorkerResponse{Item: item}, nil
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

func (s Service) createInRepo(ctx context.Context, worker *pb.Worker, creds *types.FetchNodeCredentialsRequest) (*servers.Worker, error) {
	const op = "workers.(Service).createInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	newWorker := servers.NewWorker(
		worker.GetScopeId(),
		servers.WithName(worker.GetName().GetValue()),
		servers.WithDescription(worker.GetDescription().GetValue()),
	)
	retWorker, err := repo.CreateWorker(ctx, newWorker, servers.WithFetchNodeCredentialsRequest(creds))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create worker"))
	}
	return retWorker, nil
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

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Worker) (*servers.Worker, error) {
	const op = "workers.(Service).updateInRepo"
	var opts []servers.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, servers.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, servers.WithName(name.GetValue()))
	}
	w := servers.NewWorker(scopeId, opts...)
	w.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateWorker(ctx, w, item.GetVersion(), dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update worker"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Worker %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
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
	case action.List, action.CreateWorkerLed:
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
	const op = "workers.toProto"
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
		if in.Type == KmsWorkerType {
			// KMS workers cannot be updated through the API
			out.AuthorizedActions = strutil.StrListDelete(action.Update.String())
		}
	}
	if outputFields.Has(globals.AddressField) && in.GetAddress() != "" {
		out.Address = in.GetAddress()
	}
	if outputFields.Has(globals.LastStatusTimeField) {
		out.LastStatusTime = in.GetLastStatusTime().GetTimestamp()
	}
	if outputFields.Has(globals.ActiveConnectionCountField) {
		out.ActiveConnectionCount = in.ActiveConnectionCount()
	}
	if outputFields.Has(globals.ConfigTagsField) && len(in.GetConfigTags()) > 0 {
		var err error
		out.ConfigTags, err = tagsToMapProto(in.GetConfigTags())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error preparing config tags proto"))
		}
	}
	if outputFields.Has(globals.CanonicalTagsField) && len(in.CanonicalTags()) > 0 {
		var err error
		out.CanonicalTags, err = tagsToMapProto(in.CanonicalTags())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error preparing canonical tags proto"))
		}
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

func validateUpdateRequest(req *pbs.UpdateWorkerRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetAddress() != "" {
			badFields[globals.AddressField] = "This is a read only field."
		}
		if req.GetItem().GetCanonicalTags() != nil {
			badFields[globals.CanonicalAddressField] = "This is a read only field."
		}
		if req.GetItem().GetConfigTags() != nil {
			badFields[globals.TagsField] = "This is a read only field."
		}
		nameString := req.GetItem().GetName().String()
		if !strutil.Printable(nameString) {
			badFields[globals.NameField] = "Contains non-printable characters"
		}
		if strings.ToLower(nameString) != nameString {
			badFields[globals.NameField] = "Must be all lowercase."
		}
		descriptionString := req.GetItem().GetDescription().String()
		if !strutil.Printable(descriptionString) {
			badFields[globals.DescriptionField] = "Contains non-printable characters."
		}
		return badFields
	}, servers.WorkerPrefix)
}

func validateCreateRequest(req *pbs.CreateWorkerLedRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		const (
			mustBeGlobalMsg  = "Must be 'global'"
			cannotBeEmptyMsg = "Cannot be empty."
			readOnlyFieldMsg = "This is a read only field."
		)
		badFields := map[string]string{}
		if scope.Global.String() != req.GetItem().GetScopeId() {
			badFields[globals.ScopeIdField] = mustBeGlobalMsg
		}
		// FIXME: in the future, we won't require this token since we'll support
		// the server led flow where a token is returned when a worker is created.
		if req.GetItem().WorkerGeneratedAuthToken == nil {
			badFields[globals.WorkerGeneratedAuthTokenField] = cannotBeEmptyMsg
		}
		if req.GetItem().Address != "" {
			badFields[globals.CanonicalAddressField] = readOnlyFieldMsg
		}
		if req.GetItem().CanonicalTags != nil {
			badFields[globals.CanonicalTagsField] = readOnlyFieldMsg
		}
		if req.GetItem().LastStatusTime != nil {
			badFields[globals.LastStatusTimeField] = readOnlyFieldMsg
		}
		if req.GetItem().AuthorizedActions != nil {
			badFields[globals.AuthorizedActionsField] = readOnlyFieldMsg
		}
		nameString := req.GetItem().GetName().String()
		if !strutil.Printable(nameString) {
			badFields[globals.NameField] = "Contains non-printable characters."
		}
		if strings.ToLower(nameString) != nameString {
			badFields[globals.NameField] = "Must be all lowercase"
		}
		descriptionString := req.GetItem().GetDescription().String()
		if !strutil.Printable(descriptionString) {
			badFields[globals.DescriptionField] = "Contains non-printable characters."
		}
		return badFields
	})
}
