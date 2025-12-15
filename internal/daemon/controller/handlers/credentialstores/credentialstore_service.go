// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package credentialstores

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentiallibraries"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/credentials"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	"github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/scopes"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	vaultTokenField        = "attributes.token"
	vaultTokenHmacField    = "attributes.token_hmac"
	vaultWorkerFilterField = "attributes.worker_filter"
	caCertsField           = "attributes.ca_cert"
	clientCertField        = "attributes.client_certificate"
	clientCertKeyField     = "attributes.certificate_key"
	domain                 = "credential"
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

	vaultCollectionTypeMap = map[resource.Type]action.ActionSet{
		resource.CredentialLibrary: credentiallibraries.CollectionActions,
	}
	staticCollectionTypeMap = map[resource.Type]action.ActionSet{
		resource.Credential: credentials.CollectionActions,
	}

	additionalResourceGrants = []resource.Type{
		resource.Credential,
		resource.CredentialLibrary,
	}

	validateVaultWorkerFilterFn = vaultWorkerFilterUnsupported
	vaultWorkerFilterToProto    = false
)

func vaultWorkerFilterUnsupported(string) error {
	return fmt.Errorf("Worker Filter field is not supported in OSS")
}

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.CredentialStore{}, &store.Token{}, &store.ClientCertificate{}},
		handlers.MaskSource{&pb.CredentialStore{}, &pb.VaultCredentialStoreAttributes{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove IdActionsMap and CollectionActions package variables
	action.RegisterResource(resource.CredentialStore, IdActions, CollectionActions)
}

// Service handles request as described by the pbs.CredentialStoreServiceServer interface.
type Service struct {
	pbs.UnsafeCredentialStoreServiceServer

	iamRepoFn    common.IamRepoFactory
	vaultRepoFn  common.VaultCredentialRepoFactory
	staticRepoFn common.StaticCredentialRepoFactory
	storeRepoFn  common.CredentialStoreRepoFactory
	maxPageSize  uint
}

var _ pbs.CredentialStoreServiceServer = (*Service)(nil)

// NewService returns a credential store service which handles credential store related requests to boundary.
func NewService(
	ctx context.Context,
	iamRepo common.IamRepoFactory,
	vaultRepo common.VaultCredentialRepoFactory,
	staticRepo common.StaticCredentialRepoFactory,
	storeRepoFn common.CredentialStoreRepoFactory,
	maxPageSize uint,
) (Service, error) {
	const op = "credentialstores.NewService"
	if iamRepo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if vaultRepo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing vault credential repository")
	}
	if staticRepo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing static credential repository")
	}
	if storeRepoFn == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing credential store repo")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{
		iamRepoFn:    iamRepo,
		vaultRepoFn:  vaultRepo,
		staticRepoFn: staticRepo,
		storeRepoFn:  storeRepoFn,
		maxPageSize:  maxPageSize,
	}, nil
}

// ListCredentialStores implements the interface pbs.CredentialStoreServiceServer
func (s Service) ListCredentialStores(ctx context.Context, req *pbs.ListCredentialStoresRequest) (*pbs.ListCredentialStoresResponse, error) {
	const op = "credentialstores.(Service).ListCredentialStores"

	if err := validateListRequest(ctx, req); err != nil {
		return nil, errors.Wrap(ctx, err, op)
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
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.CredentialStore, req.GetRecursive())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}
	var filterItemFn func(ctx context.Context, item credential.Store) (bool, error)
	switch {
	case req.GetFilter() != "":
		// Only use a filter if we need to
		filter, err := handlers.NewFilter(ctx, req.GetFilter())
		if err != nil {
			return nil, err
		}
		// TODO: replace the need for this function with some way to convert the `filter`
		// to a domain type. This would allow filtering to happen in the domain, and we could
		// remove this callback altogether.
		filterItemFn = func(ctx context.Context, item credential.Store) (bool, error) {
			outputOpts, ok, err := newOutputOpts(ctx, item, authResults, scopeInfoMap)
			if err != nil {
				return false, err
			}
			if !ok {
				return false, nil
			}
			pbItem, err := toProto(ctx, item, outputOpts...)
			if err != nil {
				return false, err
			}

			filterable, err := subtypes.Filterable(ctx, pbItem)
			if err != nil {
				return false, err
			}
			return filter.Match(filterable), nil
		}
	default:
		filterItemFn = func(ctx context.Context, item credential.Store) (bool, error) {
			return true, nil
		}
	}
	repo, err := s.storeRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var listResp *pagination.ListResponse[credential.Store]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = credential.ListStores(ctx, grantsHash, pageSize, filterItemFn, repo, scopeIds)
		if err != nil {
			return nil, err
		}
	} else {

		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.CredentialStore, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = credential.ListStoresPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = credential.ListStoresRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = credential.ListStoresRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, scopeIds)
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.CredentialStore, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok, err := newOutputOpts(ctx, item, authResults, scopeInfoMap)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if !ok {
			continue
		}
		pbItem, err := toProto(ctx, item, outputOpts...)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		finalItems = append(finalItems, pbItem)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListCredentialStoresResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL_STORE)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// GetCredentialStore implements the interface pbs.CredentialStoreServiceServer.
func (s Service) GetCredentialStore(ctx context.Context, req *pbs.GetCredentialStoreRequest) (*pbs.GetCredentialStoreResponse, error) {
	const op = "credentialstores.(Service).GetCredentialStore"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	cs, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cs.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, authResults.Scope, cs.GetPublicId())
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := toProto(ctx, cs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetCredentialStoreResponse{Item: item}, nil
}

// CreateCredentialStore implements the interface pbs.CredentialStoreServiceServer.
func (s Service) CreateCredentialStore(ctx context.Context, req *pbs.CreateCredentialStoreRequest) (*pbs.CreateCredentialStoreResponse, error) {
	const op = "credentialstores.(Service).CreateCredentialStore"

	if err := validateCreateRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	cs, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cs.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, authResults.Scope, cs.GetPublicId())
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := toProto(ctx, cs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateCredentialStoreResponse{
		Item: item,
		Uri:  fmt.Sprintf("credential-stores/%s", item.GetId()),
	}, nil
}

// UpdateCredentialStore implements the interface pbs.CredentialStoreServiceServer.
func (s Service) UpdateCredentialStore(ctx context.Context, req *pbs.UpdateCredentialStoreRequest) (*pbs.UpdateCredentialStoreResponse, error) {
	const op = "credentialstores.(Service).UpdateCredentialStore"

	if err := validateUpdateRequest(ctx, req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	cs, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cs.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, authResults.Scope, cs.GetPublicId())
		if err != nil {
			return nil, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}

	item, err := toProto(ctx, cs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateCredentialStoreResponse{Item: item}, nil
}

// DeleteCredentialStore implements the interface pbs.CredentialStoreServiceServer.
func (s Service) DeleteCredentialStore(ctx context.Context, req *pbs.DeleteCredentialStoreRequest) (*pbs.DeleteCredentialStoreResponse, error) {
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

func (s Service) getFromRepo(ctx context.Context, id string) (credential.Store, error) {
	const op = "credentialstores.(Service).getFromRepo"

	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case vault.Subtype:
		repo, err := s.vaultRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cs, err := repo.LookupCredentialStore(ctx, id)
		if err != nil && !errors.IsNotFoundError(err) {
			return nil, errors.Wrap(ctx, err, op)
		}
		if cs != nil {
			return cs, nil
		}

	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cs, err := repo.LookupCredentialStore(ctx, id)
		if err != nil && !errors.IsNotFoundError(err) {
			return nil, errors.Wrap(ctx, err, op)
		}
		if cs != nil {
			return cs, nil
		}
	}

	return nil, handlers.NotFoundErrorf("credential store %q not found", id)
}

func (s Service) createInRepo(ctx context.Context, projId string, item *pb.CredentialStore) (credential.Store, error) {
	const op = "credentialstores.(Service).createInRepo"

	switch item.Type {
	case vault.Subtype.String():
		cs, err := toStorageVaultStore(ctx, projId, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.vaultRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, err := repo.CreateCredentialStore(ctx, cs)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create credential store"))
		}
		return out, nil

	case static.Subtype.String():
		cs, err := toStorageStaticStore(ctx, projId, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, err := repo.CreateCredentialStore(ctx, cs)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create credential store"))
		}
		return out, nil

	default:
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create credential store, unknown type.")
	}
}

func (s Service) updateInRepo(ctx context.Context, projId, id string, mask []string, item *pb.CredentialStore) (credential.Store, error) {
	const op = "credentialstores.(Service).updateInRepo"

	var out credential.Store
	var rowsUpdated int

	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case vault.Subtype:
		cs, err := toStorageVaultStore(ctx, projId, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cs.PublicId = id

		repo, err := s.vaultRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, rowsUpdated, err = repo.UpdateCredentialStore(ctx, cs, item.GetVersion(), dbMask)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential store"))
		}

	case static.Subtype:
		cs, err := toStorageStaticStore(ctx, projId, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cs.PublicId = id

		repo, err := s.staticRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, rowsUpdated, err = repo.UpdateCredentialStore(ctx, cs, item.GetVersion(), dbMask)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential store"))
		}
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Credential Store %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	const op = "credentialstores.(Service).deleteFromRepo"
	var rows int

	switch globals.ResourceInfoFromPrefix(id).Subtype {
	case vault.Subtype:
		repo, err := s.vaultRepoFn()
		if err != nil {
			return false, err
		}
		rows, err = repo.DeleteCredentialStore(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return false, nil
			}
			return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete credential store"))
		}

	case static.Subtype:
		repo, err := s.staticRepoFn()
		if err != nil {
			return false, err
		}
		rows, err = repo.DeleteCredentialStore(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return false, nil
			}
			return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete credential store"))
		}
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
	vaultRepo, err := s.vaultRepoFn()
	if err != nil {
		res.Error = err
		return res
	}
	staticRepo, err := s.staticRepoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive), auth.WithFetchAdditionalResourceGrants(additionalResourceGrants...)}
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
		switch globals.ResourceInfoFromPrefix(id).Subtype {
		case vault.Subtype:
			cs, err := vaultRepo.LookupCredentialStore(ctx, id)
			if err != nil {
				res.Error = err
				return res
			}
			if cs == nil {
				res.Error = handlers.NotFoundError()
				return res
			}
			parentId = cs.GetProjectId()

		case static.Subtype:
			var err error
			cs, err := staticRepo.LookupCredentialStore(ctx, id)
			if err != nil {
				res.Error = err
				return res
			}
			if cs == nil {
				res.Error = handlers.NotFoundError()
				return res
			}
			parentId = cs.GetProjectId()
		}
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, resource.CredentialStore, opts...)
}

func newOutputOpts(
	ctx context.Context,
	item credential.Store,
	authResults auth.VerifyResults,
	authzScopes map[string]*scopes.ScopeInfo,
) ([]handlers.Option, bool, error) {
	res := perms.Resource{
		Type:          resource.CredentialStore,
		Id:            item.GetPublicId(),
		ScopeId:       item.GetProjectId(),
		ParentScopeId: authzScopes[item.GetProjectId()].GetParentScopeId(),
	}
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false, nil
	}

	outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
	outputOpts := make([]handlers.Option, 0, 3)
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authzScopes[item.GetProjectId()]))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, authzScopes[item.GetProjectId()], item.GetPublicId())
		if err != nil {
			return nil, false, err
		}
		outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
	}
	return outputOpts, true, nil
}

func toProto(ctx context.Context, in credential.Store, opt ...handlers.Option) (*pb.CredentialStore, error) {
	const op = "credentialstores.toProto"

	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building credential store proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.CredentialStore{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetProjectId()
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = globals.ResourceInfoFromPrefix(in.GetPublicId()).Subtype.String()
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
	if outputFields.Has(globals.AttributesField) {
		switch globals.ResourceInfoFromPrefix(in.GetPublicId()).Subtype {
		case vault.Subtype:
			vaultIn, ok := in.(*vault.CredentialStore)
			if !ok {
				return nil, errors.New(ctx, errors.Internal, op, "unable to cast to vault credential store")
			}
			attrs := &pb.VaultCredentialStoreAttributes{
				Address: wrapperspb.String(vaultIn.GetVaultAddress()),
			}
			if vaultIn.GetNamespace() != "" {
				attrs.Namespace = wrapperspb.String(vaultIn.GetNamespace())
			}
			if len(vaultIn.GetCaCert()) != 0 {
				attrs.CaCert = wrapperspb.String(string(vaultIn.GetCaCert()))
			}
			if vaultIn.GetTlsServerName() != "" {
				attrs.TlsServerName = wrapperspb.String(vaultIn.GetTlsServerName())
			}
			if vaultIn.GetTlsSkipVerify() {
				attrs.TlsSkipVerify = wrapperspb.Bool(vaultIn.GetTlsSkipVerify())
			}
			if vaultIn.Token() != nil {
				attrs.TokenHmac = base64.RawURLEncoding.EncodeToString(vaultIn.Token().GetTokenHmac())
				attrs.TokenStatus = vaultIn.Token().GetStatus()
			}
			if vaultIn.GetWorkerFilter() != "" {
				if vaultWorkerFilterToProto {
					attrs.WorkerFilter = wrapperspb.String(vaultIn.GetWorkerFilter())
				}
			}
			if cc := vaultIn.ClientCertificate(); cc != nil {
				if len(cc.GetCertificate()) != 0 {
					attrs.ClientCertificate = wrapperspb.String(string(cc.GetCertificate()))
				}
				attrs.ClientCertificateKeyHmac = base64.RawURLEncoding.EncodeToString(cc.GetCertificateKeyHmac())
			}

			out.Attrs = &pb.CredentialStore_VaultCredentialStoreAttributes{
				VaultCredentialStoreAttributes: attrs,
			}
		}
	}
	return &out, nil
}

func toStorageStaticStore(ctx context.Context, scopeId string, in *pb.CredentialStore) (out *static.CredentialStore, err error) {
	const op = "credentialstores.toStorageStaticStore"
	var opts []static.Option
	if in.GetName() != nil {
		opts = append(opts, static.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, static.WithDescription(in.GetDescription().GetValue()))
	}

	cs, err := static.NewCredentialStore(scopeId, opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential store for creation"))
	}
	return cs, err
}

func toStorageVaultStore(ctx context.Context, scopeId string, in *pb.CredentialStore) (out *vault.CredentialStore, err error) {
	const op = "credentialstores.toStorageVaultStore"
	var opts []vault.Option
	if in.GetName() != nil {
		opts = append(opts, vault.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, vault.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetVaultCredentialStoreAttributes()
	if attrs.GetTlsServerName() != nil {
		opts = append(opts, vault.WithTlsServerName(attrs.GetTlsServerName().GetValue()))
	}
	if attrs.GetTlsSkipVerify().GetValue() {
		opts = append(opts, vault.WithTlsSkipVerify(attrs.GetTlsSkipVerify().GetValue()))
	}
	if attrs.GetNamespace().GetValue() != "" {
		opts = append(opts, vault.WithNamespace(attrs.GetNamespace().GetValue()))
	}
	if attrs.GetWorkerFilter().GetValue() != "" {
		opts = append(opts, vault.WithWorkerFilter(attrs.GetWorkerFilter().GetValue()))
	}
	if attrs.GetAddress().GetValue() != "" {
		addr, err := parseutil.NormalizeAddr(attrs.GetAddress().GetValue())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		attrs.Address = wrapperspb.String(addr)
	}

	// TODO (ICU-1478 and ICU-1479): Update the vault's interface around ca cert to match oidc's,
	//  accepting x509.Certificate instead of []byte
	if attrs.GetCaCert() != nil {
		opts = append(opts, vault.WithCACert([]byte(attrs.GetCaCert().GetValue())))
	}
	pemCerts, pemPk, err := extractClientCertAndPk(ctx, attrs.GetClientCertificate().GetValue(), attrs.GetClientCertificateKey().GetValue())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if len(pemCerts) != 0 {
		var cert []byte
		for _, c := range pemCerts {
			cert = append(cert, pem.EncodeToMemory(c)...)
		}
		var pk []byte
		if pemPk != nil {
			pk = pem.EncodeToMemory(pemPk)
		}
		cc, err := vault.NewClientCertificate(ctx, cert, pk)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		opts = append(opts, vault.WithClientCert(cc))
	}

	cs, err := vault.NewCredentialStore(scopeId, attrs.GetAddress().GetValue(), []byte(attrs.GetToken().GetValue()), opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential store for creation"))
	}
	return cs, err
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetCredentialStoreRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.VaultCredentialStorePrefix, globals.StaticCredentialStorePrefix, globals.StaticCredentialStorePreviousPrefix)
}

func validateCreateRequest(ctx context.Context, req *pbs.CreateCredentialStoreRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Project.Prefix()) {
			badFields["scope_id"] = "This field must be a valid project scope id."
		}
		switch req.GetItem().GetType() {
		case vault.Subtype.String():
			attrs := req.GetItem().GetVaultCredentialStoreAttributes()
			if attrs == nil {
				badFields[globals.AttributesField] = "Attributes are required for creating a vault credential store"
			}

			if attrs.GetAddress().GetValue() == "" {
				badFields[globals.AttributesAddressField] = "Field required for creating a vault credential store."
			}
			if attrs.GetToken().GetValue() == "" {
				badFields[vaultTokenField] = "Field required for creating a vault credential store."
			}
			if attrs.GetTokenHmac() != "" {
				badFields[vaultTokenHmacField] = "This is a read only field."
			}
			if attrs.GetWorkerFilter().GetValue() != "" {
				err := validateVaultWorkerFilterFn(attrs.WorkerFilter.GetValue())
				if err != nil {
					badFields[vaultWorkerFilterField] = err.Error()
				}
			}
			// TODO(ICU-1478 and ICU-1479): Validate client and CA certificate payloads
			_, err := decodePemBlocks(ctx, attrs.GetCaCert().GetValue())
			if attrs.GetCaCert() != nil && err != nil {
				badFields[caCertsField] = "Incorrectly formatted value."
			}

			cs, pk, err := extractClientCertAndPk(ctx, attrs.GetClientCertificate().GetValue(), attrs.GetClientCertificateKey().GetValue())
			if err != nil {
				badFields[clientCertField] = fmt.Sprintf("Invalid values: %q", err.Error())
			}
			if attrs.GetClientCertificate() == nil && attrs.GetClientCertificateKey() != nil {
				badFields[clientCertKeyField] = "Cannot set a client certificate private key without the client certificate."
			}
			if len(cs) > 0 && pk == nil {
				badFields[clientCertField] = "Cannot set a client certificate without a private key."
			}
		case static.Subtype.String():
			// No additional validation required for static credential store
		default:
			badFields[globals.TypeField] = "This is a required field and must be a known credential store type."
		}
		return badFields
	})
}

func validateUpdateRequest(ctx context.Context, req *pbs.UpdateCredentialStoreRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
		case vault.Subtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != vault.Subtype.String() {
				badFields["type"] = "Cannot modify resource type."
			}
			attrs := req.GetItem().GetVaultCredentialStoreAttributes()
			if attrs != nil {
				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), globals.AttributesAddressField) &&
					attrs.GetAddress().GetValue() == "" {
					badFields[globals.AttributesAddressField] = "This is a required field and cannot be unset."
				}
				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), vaultTokenField) &&
					attrs.GetToken().GetValue() == "" {
					badFields[vaultTokenField] = "This is a required field and cannot be unset."
				}
				if attrs.GetTokenHmac() != "" {
					badFields[vaultTokenHmacField] = "This is a read only field."
				}
				if attrs.WorkerFilter.GetValue() != "" {
					err := validateVaultWorkerFilterFn(attrs.WorkerFilter.GetValue())
					if err != nil {
						badFields[vaultWorkerFilterField] = err.Error()
					}
				}

				// TODO(ICU-1478 and ICU-1479): Validate client and CA certificate payloads
				_, err := decodePemBlocks(ctx, attrs.GetCaCert().GetValue())
				if attrs.GetCaCert() != nil && err != nil {
					badFields[caCertsField] = "Incorrectly formatted value."
				}

				_, _, err = extractClientCertAndPk(ctx, attrs.GetClientCertificate().GetValue(), attrs.GetClientCertificateKey().GetValue())
				if err != nil {
					badFields[clientCertField] = fmt.Sprintf("Invalid values: %q", err.Error())
				}
			}
		}
		return badFields
	}, globals.VaultCredentialStorePrefix, globals.StaticCredentialStorePrefix, globals.StaticCredentialStorePreviousPrefix)
}

func validateDeleteRequest(req *pbs.DeleteCredentialStoreRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.VaultCredentialStorePrefix, globals.StaticCredentialStorePrefix, globals.StaticCredentialStorePreviousPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListCredentialStoresRequest) error {
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

func calculateAuthorizedCollectionActions(ctx context.Context, authResults auth.VerifyResults, itemScopeInfo *scopes.ScopeInfo, itemId string) (map[string]*structpb.ListValue, error) {
	var collectionActions map[string]*structpb.ListValue
	var err error
	switch globals.ResourceInfoFromPrefix(itemId).Subtype {
	case vault.Subtype:
		collectionActions, err = auth.CalculateAuthorizedCollectionActions(ctx, authResults, vaultCollectionTypeMap, itemScopeInfo, itemId)

	case static.Subtype:
		collectionActions, err = auth.CalculateAuthorizedCollectionActions(ctx, authResults, staticCollectionTypeMap, itemScopeInfo, itemId)
	}
	if err != nil {
		return nil, err
	}

	return collectionActions, nil
}
