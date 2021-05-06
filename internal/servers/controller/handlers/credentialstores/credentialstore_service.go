package credentialstores

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/credentialstores"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/common/scopeids"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
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
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.CredentialStore{}, &store.Token{}, &store.ClientCertificate{}},
		handlers.MaskSource{&pb.CredentialStore{}, &pb.VaultCredentialStoreAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.CredentialStoreServiceServer interface.
type Service struct {
	pbs.UnimplementedCredentialStoreServiceServer

	iamRepoFn common.IamRepoFactory
	repoFn    common.VaultCredentialRepoFactory
}

// NewService returns a credential store service which handles credential store related requests to boundary.
func NewService(repo common.VaultCredentialRepoFactory, iamRepo common.IamRepoFactory) (Service, error) {
	const op = "credentialstores.NewService"
	if iamRepo == nil {
		return Service{}, errors.New(errors.InvalidParameter, op, "missing iam repository")
	}
	if repo == nil {
		return Service{}, errors.New(errors.InvalidParameter, op, "missing vault credential repository")
	}
	return Service{iamRepoFn: iamRepo, repoFn: repo}, nil
}

var _ pbs.CredentialStoreServiceServer = Service{}

func (s Service) ListCredentialStores(ctx context.Context, req *pbs.ListCredentialStoresRequest) (*pbs.ListCredentialStoresResponse, error) {
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
		ctx, s.iamRepoFn, authResults, req.GetScopeId(), resource.CredentialStore, req.GetRecursive(), false)
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

		item, err := toProto(item, outputOpts...)
		if err != nil {
			return nil, err
		}

		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListCredentialStoresResponse{Items: finalItems}, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeIds []string) ([]*vault.CredentialStore, error) {
	const op = "credentialstores.(Service).listFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	csl, err := repo.ListCredentialStores(ctx, scopeIds)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	return csl, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		res.Error = err
		return res
	}
	repo, err := s.repoFn()
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
		cs, err := repo.LookupCredentialStore(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if cs == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = cs.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(in credential.CredentialStore, opt ...handlers.Option) (*pb.CredentialStore, error) {
	const op = "credentialstores.toProto"

	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building group proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.CredentialStore{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.ScopeIdField) {
		out.ScopeId = in.GetScopeId()
	}
	if outputFields.Has(globals.TypeField) {
		out.Type = credential.SubtypeFromId(in.GetPublicId()).String()
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
	if outputFields.Has(globals.AttributesField) {
		switch credential.SubtypeFromId(in.GetPublicId()) {
		case credential.VaultSubtype:
			vaultIn, ok := in.(*vault.CredentialStore)
			if !ok {
				return nil, errors.New(errors.Internal, op, "unable to cast to vault credential store")
			}
			attrs := &pb.VaultCredentialStoreAttributes{
				Address: vaultIn.GetVaultAddress(),
			}
			if vaultIn.GetNamespace() != "" {
				attrs.Namespace = wrapperspb.String(vaultIn.GetNamespace())
			}
			if len(vaultIn.GetCaCert()) != 0 {
				attrs.VaultCaCert = wrapperspb.String(string(vaultIn.GetCaCert()))
			}
			if vaultIn.GetTlsServerName() != "" {
				attrs.TlsServerName = wrapperspb.String(vaultIn.GetTlsServerName())
			}
			if vaultIn.GetTlsSkipVerify() {
				attrs.TlsSkipVerify = wrapperspb.Bool(vaultIn.GetTlsSkipVerify())
			}
			// TODO: Add vault token hmac and client cert read only fields.

			var err error
			if out.Attributes, err = handlers.ProtoToStruct(attrs); err != nil {
				return nil, errors.Wrap(err, op)
			}
		}
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetCredentialStoreRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, vault.CredentialStorePrefix)
}

func validateCreateRequest(req *pbs.CreateCredentialStoreRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetScopeId()), scope.Project.Prefix()) {
			badFields["scope_id"] = "This field must be a valid project scope id."
		}
		switch credential.SubtypeFromType(req.GetItem().GetType()) {
		case credential.VaultSubtype:
		default:
			badFields["type"] = "This is a required field and must be a known credential store type."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateCredentialStoreRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch credential.SubtypeFromId(req.GetId()) {
		case credential.VaultSubtype:
			if req.GetItem().GetType() != "" && credential.SubtypeFromType(req.GetItem().GetType()) != credential.VaultSubtype {
				badFields["type"] = "Cannot modify resource type."
			}
		}
		return badFields
	}, vault.CredentialStorePrefix)
}

func validateDeleteRequest(req *pbs.DeleteCredentialStoreRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, vault.CredentialStorePrefix)
}

func validateListRequest(req *pbs.ListCredentialStoresRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetScopeId()), scope.Project.Prefix()) &&
		!req.GetRecursive() {
		badFields["scope_id"] = "This field must be a valid project scope ID or the list operation must be recursive."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
