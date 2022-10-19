package workers

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/server/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/util"
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
		action.AddWorkerTags,
		action.SetWorkerTags,
		action.RemoveWorkerTags,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.CreateControllerLed,
		action.CreateWorkerLed,
		action.List,
		action.ReadCertificateAuthority,
		action.ReinitializeCertificateAuthority,
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
	pbs.UnsafeWorkerServiceServer

	repoFn       common.ServersRepoFactory
	workerAuthFn common.WorkerAuthRepoStorageFactory
	iamRepoFn    common.IamRepoFactory
}

var _ pbs.WorkerServiceServer = (*Service)(nil)

// NewService returns a worker service which handles worker related requests to boundary.
func NewService(ctx context.Context, repo common.ServersRepoFactory, iamRepoFn common.IamRepoFactory,
	workerAuthFn common.WorkerAuthRepoStorageFactory,
) (Service, error) {
	const op = "workers.NewService"
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing server repository")
	}
	if iamRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if workerAuthFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing worker auth repository")
	}
	return Service{repoFn: repo, iamRepoFn: iamRepoFn, workerAuthFn: workerAuthFn}, nil
}

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

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
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

// CreateWorkerLed implements the interface pbs.WorkerServiceServer and handles
// a request to create a new worker and consume a worker-generated authorization
// request
func (s Service) CreateWorkerLed(ctx context.Context, req *pbs.CreateWorkerLedRequest) (*pbs.CreateWorkerLedResponse, error) {
	const op = "workers.(Service).CreateWorkerLed"

	act := action.CreateWorkerLed
	item := req.GetItem()

	if err := validateCreateRequest(item, act); err != nil {
		return nil, err
	}

	reqBytes, err := base58.FastBase58Decoding(item.WorkerGeneratedAuthToken.GetValue())
	if err != nil {
		return nil, fmt.Errorf("%s: error decoding node_credentials_token: %w", op, err)
	}
	// Decode the proto into the request
	creds := new(types.FetchNodeCredentialsRequest)
	if err := proto.Unmarshal(reqBytes, creds); err != nil {
		return nil, fmt.Errorf("%s: error unmarshaling node_credentials_token: %w", op, err)
	}

	out, err := s.createCommon(ctx, item, act, server.WithFetchNodeCredentialsRequest(creds))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return &pbs.CreateWorkerLedResponse{Item: out}, nil
}

// CreateControllerLed implements the interface pbs.WorkerServiceServer and handles
// a request to create a new worker, generating and returning an activation
// token
func (s Service) CreateControllerLed(ctx context.Context, req *pbs.CreateControllerLedRequest) (*pbs.CreateControllerLedResponse, error) {
	const op = "workers.(Service).CreateControllerLed"
	act := action.CreateControllerLed

	if err := validateCreateRequest(req.GetItem(), act); err != nil {
		return nil, err
	}

	out, err := s.createCommon(ctx, req.GetItem(), act, server.WithCreateControllerLedActivationToken(true))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return &pbs.CreateControllerLedResponse{Item: out}, nil
}

func (s Service) createCommon(ctx context.Context, in *pb.Worker, act action.Type, opt ...server.Option) (*pb.Worker, error) {
	const op = "workers.(Service).createCommon"

	authResults := s.authResult(ctx, in.GetScopeId(), act)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	created, err := s.createInRepo(ctx, in, opt...)
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

	return item, nil
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

// AddWorkerTags implements the interface pbs.WorkerServiceServer.
func (s Service) AddWorkerTags(ctx context.Context, req *pbs.AddWorkerTagsRequest) (*pbs.AddWorkerTagsResponse, error) {
	const op = "workers.(Service).AddWorkerTags"

	if err := validateAddTagsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddWorkerTags)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	w, err := s.addTagsInRepo(ctx, req.GetId(), req.GetVersion(), req.GetApiTags())
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

	return &pbs.AddWorkerTagsResponse{Item: item}, nil
}

// SetWorkerTags implements the interface pbs.WorkerServiceServer.
func (s Service) SetWorkerTags(ctx context.Context, req *pbs.SetWorkerTagsRequest) (*pbs.SetWorkerTagsResponse, error) {
	const op = "workers.(Service).SetWorkerTags"

	if err := validateSetTagsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetWorkerTags)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	w, err := s.setTagsInRepo(ctx, req.GetId(), req.GetVersion(), req.GetApiTags())
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

	return &pbs.SetWorkerTagsResponse{Item: item}, nil
}

// RemoveWorkerTags implements the interface pbs.WorkerServiceServer.
func (s Service) RemoveWorkerTags(ctx context.Context, req *pbs.RemoveWorkerTagsRequest) (*pbs.RemoveWorkerTagsResponse, error) {
	const op = "workers.(Service).RemoveWorkerTags"

	if err := validateRemoveTagsRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveWorkerTags)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	w, err := s.removeTagsInRepo(ctx, req.GetId(), req.GetVersion(), req.GetApiTags())
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

	return &pbs.RemoveWorkerTagsResponse{Item: item}, nil
}

// ReadCertificateAuthority will list the next and current certificates for the worker certificate authority
func (s Service) ReadCertificateAuthority(ctx context.Context, req *pbs.ReadCertificateAuthorityRequest) (*pbs.ReadCertificateAuthorityResponse, error) {
	const op = "workers.(Service).ReadCertificateAuthority"
	if err := validateReadCaRequest(req); err != nil {
		return nil, err
	}

	authResults := s.authResult(ctx, req.GetScopeId(), action.ReadCertificateAuthority)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	caProto, err := s.listCertificateAuthorityFromRepo(ctx)
	if err != nil {
		return nil, err
	}

	ca := certificateAuthorityToProto(caProto)
	return &pbs.ReadCertificateAuthorityResponse{Item: ca}, nil
}

// ReinitializeCertificateAuthority will delete and regenerate the next and current certificates for the worker certificate authority
func (s Service) ReinitializeCertificateAuthority(ctx context.Context, req *pbs.ReinitializeCertificateAuthorityRequest) (*pbs.ReinitializeCertificateAuthorityResponse, error) {
	const op = "workers.(Service).ReinitializeCertificateAuthority"
	if err := validateReinitCaRequest(req); err != nil {
		return nil, err
	}

	authResults := s.authResult(ctx, req.GetScopeId(), action.ReinitializeCertificateAuthority)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	repo, err := s.workerAuthFn()
	if err != nil {
		return nil, err
	}

	rootCerts, err := server.ReinitializeRoots(ctx, repo)
	if err != nil {
		return nil, err
	}

	ca := certificateAuthorityToProto(rootCerts)

	return &pbs.ReinitializeCertificateAuthorityResponse{Item: ca}, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*server.Worker, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	wl, err := repo.ListWorkers(ctx, scopeIds, server.WithLiveness(-1))
	if err != nil {
		return nil, err
	}
	return wl, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*server.Worker, error) {
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

func (s Service) createInRepo(ctx context.Context, worker *pb.Worker, opt ...server.Option) (*server.Worker, error) {
	const op = "workers.(Service).createInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	newWorker := server.NewWorker(
		worker.GetScopeId(),
		server.WithName(worker.GetName().GetValue()),
		server.WithDescription(worker.GetDescription().GetValue()),
	)
	retWorker, err := repo.CreateWorker(ctx, newWorker, opt...)
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

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Worker) (*server.Worker, error) {
	const op = "workers.(Service).updateInRepo"
	var opts []server.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, server.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, server.WithName(name.GetValue()))
	}
	w := server.NewWorker(scopeId, opts...)
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

func (s Service) addTagsInRepo(ctx context.Context, workerId string, workerVersion uint32, addTags map[string]*structpb.ListValue) (*server.Worker, error) {
	const op = "workers.(Service).addTagsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}

	tags := make([]*server.Tag, 0, len(addTags))
	for k, lv := range addTags {
		for _, v := range lv.GetValues() {
			tags = append(tags, &server.Tag{Key: k, Value: v.GetStringValue()})
		}
	}
	_, err = repo.AddWorkerTags(ctx, workerId, workerVersion, tags)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add worker tags in repo: %v.", err)
	}
	w, err := repo.LookupWorker(ctx, workerId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up worker after adding tags"))
	}
	if w == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to look up worker after adding tags.")
	}
	return w, nil
}

func (s Service) setTagsInRepo(ctx context.Context, workerId string, workerVersion uint32, setTags map[string]*structpb.ListValue) (*server.Worker, error) {
	const op = "workers.(Service).setTagsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}

	tags := make([]*server.Tag, 0, len(setTags))
	for k, lv := range setTags {
		for _, v := range lv.GetValues() {
			tags = append(tags, &server.Tag{Key: k, Value: v.GetStringValue()})
		}
	}
	_, err = repo.SetWorkerTags(ctx, workerId, workerVersion, tags)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set worker tags in repo: %v.", err)
	}
	w, err := repo.LookupWorker(ctx, workerId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up worker after setting tags"))
	}
	if w == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to look up worker after setting tags.")
	}
	return w, nil
}

func (s Service) removeTagsInRepo(ctx context.Context, workerId string, workerVersion uint32, removeTags map[string]*structpb.ListValue) (*server.Worker, error) {
	const op = "workers.(Service).removeTagsInRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}

	tags := make([]*server.Tag, 0, len(removeTags))
	for k, lv := range removeTags {
		for _, v := range lv.GetValues() {
			tags = append(tags, &server.Tag{Key: k, Value: v.GetStringValue()})
		}
	}
	_, err = repo.DeleteWorkerTags(ctx, workerId, workerVersion, tags)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove worker tags in repo: %v.", err)
	}
	w, err := repo.LookupWorker(ctx, workerId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to look up worker after removing tags"))
	}
	if w == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to look up worker after removing tags.")
	}
	return w, nil
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
	case action.List, action.CreateWorkerLed, action.CreateControllerLed, action.ReadCertificateAuthority, action.ReinitializeCertificateAuthority:
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

func (s Service) listCertificateAuthorityFromRepo(ctx context.Context) (*types.RootCertificates, error) {
	repo, err := s.workerAuthFn()
	if err != nil {
		return nil, err
	}

	certs := &types.RootCertificates{Id: server.CaId}
	err = repo.Load(ctx, certs)
	if err != nil {
		return nil, err
	}

	return certs, nil
}

func certificateAuthorityToProto(in *types.RootCertificates) *pb.CertificateAuthority {
	certs := make([]*pb.Certificate, 0)

	current := in.GetCurrent()
	currentSha := sha256.Sum256(current.PublicKeyPkix)
	currentCert := &pb.Certificate{
		Id:              string(server.CurrentState),
		PublicKeySha256: hex.EncodeToString(currentSha[:]),
		NotBeforeTime:   current.NotBefore,
		NotAfterTime:    current.NotAfter,
	}
	certs = append(certs, currentCert)

	next := in.GetNext()
	nextSha := sha256.Sum256(next.PublicKeyPkix)
	nextCert := &pb.Certificate{
		Id:              string(server.NextState),
		PublicKeySha256: hex.EncodeToString(nextSha[:]),
		NotBeforeTime:   next.NotBefore,
		NotAfterTime:    next.NotAfter,
	}
	certs = append(certs, nextCert)

	return &pb.CertificateAuthority{Certs: certs}
}

func toProto(ctx context.Context, in *server.Worker, opt ...handlers.Option) (*pb.Worker, error) {
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
	if outputFields.Has(globals.ReleaseVersionField) {
		out.ReleaseVersion = in.GetReleaseVersion()
	}
	if outputFields.Has(globals.VersionField) {
		out.Version = in.GetVersion()
	}
	if outputFields.Has(globals.ScopeField) {
		out.Scope = opts.WithScope
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		out.AuthorizedActions = opts.WithAuthorizedActions
		if in.Type == KmsWorkerType && out.AuthorizedActions != nil {
			// KMS workers cannot be updated through the API
			allActions := out.AuthorizedActions
			out.AuthorizedActions = make([]string, 0, len(allActions))
			for _, act := range allActions {
				if act != action.Update.String() {
					out.AuthorizedActions = append(out.AuthorizedActions, act)
				}
			}
		}
	}
	if outputFields.Has(globals.AddressField) && in.GetAddress() != "" {
		out.Address = in.GetAddress()
	}
	if outputFields.Has(globals.TypeField) && in.GetType() != "" {
		out.Type = in.GetType()
	}
	if outputFields.Has(globals.LastStatusTimeField) {
		out.LastStatusTime = in.GetLastStatusTime().GetTimestamp()
	}
	if outputFields.Has(globals.ActiveConnectionCountField) {
		out.ActiveConnectionCount = &wrapperspb.UInt32Value{Value: in.ActiveConnectionCount()}
	}
	if outputFields.Has(globals.ControllerGeneratedActivationToken) && in.ControllerGeneratedActivationToken != "" {
		out.ControllerGeneratedActivationToken = &wrapperspb.StringValue{Value: in.ControllerGeneratedActivationToken}
	}
	if outputFields.Has(globals.ConfigTagsField) && len(in.GetConfigTags()) > 0 {
		var err error
		out.ConfigTags, err = tagsToMapProto(in.GetConfigTags())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error preparing config tags proto"))
		}
	}
	if outputFields.Has(globals.ApiTagsField) && len(in.GetApiTags()) > 0 {
		var err error
		out.ApiTags, err = tagsToMapProto(in.GetApiTags())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error preparing api tags proto"))
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
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetWorkerRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, server.WorkerPrefix)
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
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, server.WorkerPrefix)
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
	}, server.WorkerPrefix)
}

func validateCreateRequest(item *pb.Worker, act action.Type) error {
	if util.IsNil(item) {
		return handlers.InvalidArgumentErrorf("Request item is nil", nil)
	}
	switch act {
	case action.CreateWorkerLed:
	case action.CreateControllerLed:
	default:
		// This shouldn't happen because we shouldn't be routed to one of the
		// handlers if it's the wrong action, but check anyways.
		return handlers.InvalidArgumentErrorf("Invalid action", nil)
	}
	return handlers.ValidateCreateRequest(item, func() map[string]string {
		const (
			mustBeGlobalMsg  = "Must be 'global'"
			cannotBeEmptyMsg = "Cannot be empty."
			readOnlyFieldMsg = "This is a read only field."
		)
		badFields := map[string]string{}
		if scope.Global.String() != item.GetScopeId() {
			badFields[globals.ScopeIdField] = mustBeGlobalMsg
		}
		switch {
		case act == action.CreateWorkerLed && item.WorkerGeneratedAuthToken == nil:
			badFields[globals.WorkerGeneratedAuthTokenField] = cannotBeEmptyMsg
		case act == action.CreateControllerLed && item.WorkerGeneratedAuthToken != nil:
			badFields[globals.WorkerGeneratedAuthTokenField] = "Worker-generated auth tokens are not used with the controller-led creation flow."
		}
		if item.Address != "" {
			badFields[globals.CanonicalAddressField] = readOnlyFieldMsg
		}
		if item.CanonicalTags != nil {
			badFields[globals.CanonicalTagsField] = readOnlyFieldMsg
		}
		if item.ConfigTags != nil {
			badFields[globals.ConfigTagsField] = readOnlyFieldMsg
		}
		if item.LastStatusTime != nil {
			badFields[globals.LastStatusTimeField] = readOnlyFieldMsg
		}
		if item.AuthorizedActions != nil {
			badFields[globals.AuthorizedActionsField] = readOnlyFieldMsg
		}
		nameString := item.GetName().String()
		if !strutil.Printable(nameString) {
			badFields[globals.NameField] = "Name contains non-printable characters."
		}
		if strings.ToLower(nameString) != nameString {
			badFields[globals.NameField] = "Name must be all lowercase."
		}
		descriptionString := item.GetDescription().String()
		if !strutil.Printable(descriptionString) {
			badFields[globals.DescriptionField] = "Description contains non-printable characters."
		}
		return badFields
	})
}

// validateStringForDb checks a string is valid for db storage and returns a string for an error message if needed.
// returns an empty string otherwise.
func validateStringForDb(str string) string {
	switch {
	case len(str) <= 0:
		return "must be non-empty."
	case len(str) > 512:
		return "must be within 512 characters."
	default:
		return ""
	}
}

func validateAddTagsRequest(req *pbs.AddWorkerTagsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), server.WorkerPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if req.GetApiTags() == nil {
		badFields[globals.ApiTagsField] = "Must be non-empty."
	}
	for k, lv := range req.GetApiTags() {
		if err := validateStringForDb(k); err != "" {
			badFields[globals.ApiTagsField] = "Tag keys " + err
			break
		}
		if lv.GetValues() == nil {
			badFields[globals.ApiTagsField] = "Tag values must be non-empty."
			break
		}
		for _, v := range lv.GetValues() {
			if _, ok := v.GetKind().(*structpb.Value_StringValue); !ok {
				badFields[globals.ApiTagsField] = "Tag values must be strings."
				break
			}
			if err := validateStringForDb(v.GetStringValue()); err != "" {
				badFields[globals.ApiTagsField] = "Tag values " + err
				break
			}
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetTagsRequest(req *pbs.SetWorkerTagsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), server.WorkerPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	for k, lv := range req.GetApiTags() {
		if err := validateStringForDb(k); err != "" {
			badFields[globals.ApiTagsField] = "Tag keys " + err
			break
		}
		if lv.GetValues() == nil {
			badFields[globals.ApiTagsField] = "Tag values must be non-empty."
			break
		}
		for _, v := range lv.GetValues() {
			if _, ok := v.GetKind().(*structpb.Value_StringValue); !ok {
				badFields[globals.ApiTagsField] = "Tag values must be strings."
				break
			}
			if err := validateStringForDb(v.GetStringValue()); err != "" {
				badFields[globals.ApiTagsField] = "Tag values " + err
				break
			}
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveTagsRequest(req *pbs.RemoveWorkerTagsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), server.WorkerPrefix) {
		badFields[globals.IdField] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[globals.VersionField] = "Required field."
	}
	if req.GetApiTags() == nil {
		badFields[globals.ApiTagsField] = "Must be non-empty."
	}
	for k, lv := range req.GetApiTags() {
		if err := validateStringForDb(k); err != "" {
			badFields[globals.ApiTagsField] = "Tag keys " + err
			break
		}
		if lv.GetValues() == nil {
			badFields[globals.ApiTagsField] = "Tag values must be non-empty."
			break
		}
		for _, v := range lv.GetValues() {
			if _, ok := v.GetKind().(*structpb.Value_StringValue); !ok {
				badFields[globals.ApiTagsField] = "Tag values must be strings."
				break
			}
			if err := validateStringForDb(v.GetStringValue()); err != "" {
				badFields[globals.ApiTagsField] = "Tag values " + err
				break
			}
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateReadCaRequest(req *pbs.ReadCertificateAuthorityRequest) error {
	badFields := map[string]string{}
	if req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Must be 'global' when reading."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateReinitCaRequest(req *pbs.ReinitializeCertificateAuthorityRequest) error {
	badFields := map[string]string{}
	if req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "Must be 'global' when reinitializing certs."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}

	return nil
}
