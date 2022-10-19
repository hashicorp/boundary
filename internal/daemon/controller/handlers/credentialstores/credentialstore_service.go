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
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentialstores"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	addressField           = "attributes.address"
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

	vaultCollectionTypeMap = map[resource.Type]action.ActionSet{
		resource.CredentialLibrary: credentiallibraries.CollectionActions,
	}
	staticCollectionTypeMap = map[resource.Type]action.ActionSet{
		resource.Credential: credentials.CollectionActions,
	}
	validateVaultWorkerFilterFn = vaultWorkerFilterUnsupported
	vaultWorkerFilterToProto    = false
)

func vaultWorkerFilterUnsupported(string) error {
	return fmt.Errorf("Worker Filter field is not supported in OSS")
}

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.CredentialStore{}, &store.Token{}, &store.ClientCertificate{}},
		handlers.MaskSource{&pb.CredentialStore{}, &pb.VaultCredentialStoreAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.CredentialStoreServiceServer interface.
type Service struct {
	pbs.UnsafeCredentialStoreServiceServer

	iamRepoFn    common.IamRepoFactory
	vaultRepoFn  common.VaultCredentialRepoFactory
	staticRepoFn common.StaticCredentialRepoFactory
}

var _ pbs.CredentialStoreServiceServer = (*Service)(nil)

// NewService returns a credential store service which handles credential store related requests to boundary.
func NewService(
	ctx context.Context,
	vaultRepo common.VaultCredentialRepoFactory,
	staticRepo common.StaticCredentialRepoFactory,
	iamRepo common.IamRepoFactory,
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
	return Service{iamRepoFn: iamRepo, vaultRepoFn: vaultRepo, staticRepoFn: staticRepo}, nil
}

// ListCredentialStores implements the interface pbs.CredentialStoreServiceServer
func (s Service) ListCredentialStores(ctx context.Context, req *pbs.ListCredentialStoresRequest) (*pbs.ListCredentialStoresResponse, error) {
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
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.CredentialStore, req.GetRecursive())
	if err != nil {
		return nil, err
	}
	// If no scopes match, return an empty response
	if len(scopeIds) == 0 {
		return &pbs.ListCredentialStoresResponse{}, nil
	}

	csl, err := s.listFromRepo(ctx, scopeIds)
	if err != nil {
		return nil, err
	}
	if len(csl) == 0 {
		return &pbs.ListCredentialStoresResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.CredentialStore, 0, len(csl))
	res := perms.Resource{
		Type: resource.CredentialStore,
	}
	for _, item := range csl {
		res.Id = item.GetPublicId()
		res.ScopeId = item.GetProjectId()
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(scopeInfoMap[item.GetProjectId()]))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}
		if outputFields.Has(globals.AuthorizedCollectionActionsField) {
			collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, item.GetPublicId())
			if err != nil {
				return nil, err
			}
			outputOpts = append(outputOpts, handlers.WithAuthorizedCollectionActions(collectionActions))
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
	return &pbs.ListCredentialStoresResponse{Items: finalItems}, nil
}

// GetCredentialStore implements the interface pbs.CredentialStoreServiceServer.
func (s Service) GetCredentialStore(ctx context.Context, req *pbs.GetCredentialStoreRequest) (*pbs.GetCredentialStoreResponse, error) {
	const op = "credentialstores.(Service).GetCredentialStore"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cs.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, cs.GetPublicId())
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
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cs.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, cs.GetPublicId())
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
	authResults := s.authResult(ctx, req.GetId(), action.Update)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cs.GetPublicId(), IdActions).Strings()))
	}
	if outputFields.Has(globals.AuthorizedCollectionActionsField) {
		collectionActions, err := calculateAuthorizedCollectionActions(ctx, authResults, cs.GetPublicId())
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

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]credential.Store, error) {
	const op = "credentialstores.(Service).listFromRepo"

	vaultRepo, err := s.vaultRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	vaultCsl, err := vaultRepo.ListCredentialStores(ctx, scopeIds)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	staticRepo, err := s.staticRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	staticCsl, err := staticRepo.ListCredentialStores(ctx, scopeIds)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	csl := make([]credential.Store, 0, len(staticCsl)+len(vaultCsl))
	for _, s := range vaultCsl {
		csl = append(csl, s)
	}
	for _, s := range staticCsl {
		csl = append(csl, s)
	}

	return csl, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (credential.Store, error) {
	const op = "credentialstores.(Service).getFromRepo"

	switch subtypes.SubtypeFromId(domain, id) {
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

	switch subtypes.SubtypeFromId(domain, id) {
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

	switch subtypes.SubtypeFromId(domain, id) {
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

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
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
	opts := []auth.Option{auth.WithType(resource.CredentialStore), auth.WithAction(a)}
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
		switch subtypes.SubtypeFromId(domain, id) {
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
	return auth.Verify(ctx, opts...)
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
		out.Type = subtypes.SubtypeFromId(domain, in.GetPublicId()).String()
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
		switch subtypes.SubtypeFromId(domain, in.GetPublicId()) {
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
		cc, err := vault.NewClientCertificate(cert, pk)
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, vault.CredentialStorePrefix, static.CredentialStorePrefix, static.PreviousCredentialStorePrefix)
}

func validateCreateRequest(ctx context.Context, req *pbs.CreateCredentialStoreRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Project.Prefix()) {
			badFields["scope_id"] = "This field must be a valid project scope id."
		}
		switch subtypes.SubtypeFromType(domain, req.GetItem().GetType()) {
		case vault.Subtype:
			attrs := req.GetItem().GetVaultCredentialStoreAttributes()
			if attrs == nil {
				badFields[globals.AttributesField] = "Attributes are required for creating a vault credential store"
			}

			if attrs.GetAddress().GetValue() == "" {
				badFields[addressField] = "Field required for creating a vault credential store."
			}
			if attrs.GetToken().GetValue() == "" {
				badFields[vaultTokenField] = "Field required for creating a vault credential store."
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
		case static.Subtype:
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
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case vault.Subtype:
			if req.GetItem().GetType() != "" && subtypes.SubtypeFromType(domain, req.GetItem().GetType()) != vault.Subtype {
				badFields["type"] = "Cannot modify resource type."
			}
			attrs := req.GetItem().GetVaultCredentialStoreAttributes()
			if attrs != nil {
				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), addressField) &&
					attrs.GetAddress().GetValue() == "" {
					badFields[addressField] = "This is a required field and cannot be unset."
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
	}, vault.CredentialStorePrefix, static.CredentialStorePrefix, static.PreviousCredentialStorePrefix)
}

func validateDeleteRequest(req *pbs.DeleteCredentialStoreRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, vault.CredentialStorePrefix, static.CredentialStorePrefix, static.PreviousCredentialStorePrefix)
}

func validateListRequest(req *pbs.ListCredentialStoresRequest) error {
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

func calculateAuthorizedCollectionActions(ctx context.Context, authResults auth.VerifyResults, id string) (map[string]*structpb.ListValue, error) {
	var collectionActions map[string]*structpb.ListValue
	var err error
	switch subtypes.SubtypeFromId(domain, id) {
	case vault.Subtype:
		collectionActions, err = auth.CalculateAuthorizedCollectionActions(ctx, authResults, vaultCollectionTypeMap, authResults.Scope.Id, id)

	case static.Subtype:
		collectionActions, err = auth.CalculateAuthorizedCollectionActions(ctx, authResults, staticCollectionTypeMap, authResults.Scope.Id, id)
	}
	if err != nil {
		return nil, err
	}

	return collectionActions, nil
}
