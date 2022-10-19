package credentiallibraries

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	attributesPathField        = "attributes"
	vaultPathField             = "attributes.path"
	httpMethodField            = "attributes.http_method"
	httpRequestBodyField       = "attributes.http_request_body"
	credentialMappingPathField = "credential_mapping_overrides"
	domain                     = "credential"
)

// Credential mapping override attributes
const (
	usernameAttribute     string = "username_attribute"
	passwordAttribute     string = "password_attribute"
	privateKeyAttribute   string = "private_key_attribute"
	pkPassphraseAttribute string = "private_key_passphrase_attribute"
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
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.CredentialLibrary{}},
		handlers.MaskSource{&pb.CredentialLibrary{}, &pb.VaultCredentialLibraryAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.CredentialLibraryServiceServer interface.
type Service struct {
	pbs.UnsafeCredentialLibraryServiceServer

	iamRepoFn common.IamRepoFactory
	repoFn    common.VaultCredentialRepoFactory
}

var _ pbs.CredentialLibraryServiceServer = (*Service)(nil)

// NewService returns a credential library service which handles credential library related requests to boundary.
func NewService(repo common.VaultCredentialRepoFactory, iamRepo common.IamRepoFactory) (Service, error) {
	const op = "credentiallibraries.NewService"
	if iamRepo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	if repo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing vault credential repository")
	}
	return Service{iamRepoFn: iamRepo, repoFn: repo}, nil
}

// ListCredentialLibraries implements the interface pbs.CredentialLibraryServiceServer
func (s Service) ListCredentialLibraries(ctx context.Context, req *pbs.ListCredentialLibrariesRequest) (*pbs.ListCredentialLibrariesResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetCredentialStoreId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	csl, err := s.listFromRepo(ctx, req.GetCredentialStoreId())
	if err != nil {
		return nil, err
	}
	if len(csl) == 0 {
		return &pbs.ListCredentialLibrariesResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.CredentialLibrary, 0, len(csl))
	res := perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.CredentialLibrary,
		Pin:     req.GetCredentialStoreId(),
	}
	for _, item := range csl {
		res.Id = item.GetPublicId()
		authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
		if len(authorizedActions) == 0 {
			continue
		}

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserData.User.Id)
		outputOpts := make([]handlers.Option, 0, 3)
		outputOpts = append(outputOpts, handlers.WithOutputFields(&outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
			outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authorizedActions))
		}

		item, err := toProto(item, outputOpts...)
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
	return &pbs.ListCredentialLibrariesResponse{Items: finalItems}, nil
}

// GetCredentialLibrary implements the interface pbs.CredentialLibraryServiceServer.
func (s Service) GetCredentialLibrary(ctx context.Context, req *pbs.GetCredentialLibraryRequest) (*pbs.GetCredentialLibraryResponse, error) {
	const op = "credentiallibraries.(Service).GetCredentialLibrary"

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

	item, err := toProto(cs, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetCredentialLibraryResponse{Item: item}, nil
}

// CreateCredentialLibrary implements the interface pbs.CredentialLibraryServiceServer.
func (s Service) CreateCredentialLibrary(ctx context.Context, req *pbs.CreateCredentialLibraryRequest) (*pbs.CreateCredentialLibraryResponse, error) {
	const op = "credentiallibraries.(Service).CreateCredentialLibrary"

	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetCredentialStoreId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	cl, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cl.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateCredentialLibraryResponse{
		Item: item,
		Uri:  fmt.Sprintf("credential-libraries/%s", item.GetId()),
	}, nil
}

// UpdateCredentialLibrary implements the interface pbs.CredentialLibraryServiceServer.
func (s Service) UpdateCredentialLibrary(ctx context.Context, req *pbs.UpdateCredentialLibraryRequest) (*pbs.UpdateCredentialLibraryResponse, error) {
	const op = "credentiallibraries.(Service).UpdateCredentialLibrary"

	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	cur, err := repo.LookupCredentialLibrary(ctx, req.Id)
	if err != nil {
		return nil, err
	}
	currentCredentialType := credential.Type(cur.GetCredentialType())

	if err := validateUpdateRequest(req, currentCredentialType); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	cl, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem(), currentCredentialType, cur.MappingOverride)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cl.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(cl, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateCredentialLibraryResponse{Item: item}, nil
}

// DeleteCredentialLibrary implements the interface pbs.CredentialLibraryServiceServer.
func (s Service) DeleteCredentialLibrary(ctx context.Context, req *pbs.DeleteCredentialLibraryRequest) (*pbs.DeleteCredentialLibraryResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, authResults.Scope.GetId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (s Service) listFromRepo(ctx context.Context, storeId string) ([]*vault.CredentialLibrary, error) {
	const op = "credentiallibraries.(Service).listFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	csl, err := repo.ListCredentialLibraries(ctx, storeId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return csl, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (credential.Library, error) {
	const op = "credentiallibraries.(Service).getFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cs, err := repo.LookupCredentialLibrary(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, errors.Wrap(ctx, err, op)
	}
	if cs == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("credential library %q not found", id))
	}
	return cs, err
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.CredentialLibrary) (credential.Library, error) {
	const op = "credentiallibraries.(Service).createInRepo"
	cl, err := toStorageVaultLibrary(item.GetCredentialStoreId(), item)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, err := repo.CreateCredentialLibrary(ctx, scopeId, cl)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create credential library"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create credential library but no error returned from repository.")
	}
	return out, nil
}

func (s Service) updateInRepo(
	ctx context.Context,
	projId, id string,
	masks []string,
	in *pb.CredentialLibrary,
	currentCredentialType credential.Type,
	currentMapping vault.MappingOverride) (credential.Library, error,
) {
	const op = "credentiallibraries.(Service).updateInRepo"

	var dbMasks []string
	item := proto.Clone(in).(*pb.CredentialLibrary)
	item.CredentialType = string(currentCredentialType)

	mapping, update := getMappingUpdates(currentCredentialType, currentMapping, item.GetCredentialMappingOverrides().AsMap(), masks)
	if update {
		// got mapping update, append mapping override db field mask
		dbMasks = append(dbMasks, vault.MappingOverrideField)
		mappingStruct, err := structpb.NewStruct(mapping)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		item.CredentialMappingOverrides = mappingStruct
	}

	cl, err := toStorageVaultLibrary(item.GetCredentialStoreId(), item)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cl.PublicId = id

	dbMasks = append(dbMasks, maskManager.Translate(masks)...)
	if len(dbMasks) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateCredentialLibrary(ctx, projId, cl, item.GetVersion(), dbMasks)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential library"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Credential Library %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "credentiallibraries.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteCredentialLibrary(ctx, scopeId, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete credential library"))
	}
	return rows > 0, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	const op = "credentiallibraries.(Service).authResult"
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.CredentialLibrary), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		opts = append(opts, auth.WithId(id))

		switch subtypes.SubtypeFromId(domain, id) {
		case vault.Subtype:
			cl, err := repo.LookupCredentialLibrary(ctx, id)
			if err != nil {
				res.Error = err
				return res
			}
			if cl == nil {
				res.Error = handlers.NotFoundError()
				return res
			}
			parentId = cl.GetStoreId()
		default:
			res.Error = errors.New(ctx, errors.InvalidParameter, op, "unrecognized credential library subtype from id")
			return res
		}
	}

	if parentId == "" {
		res.Error = errors.New(ctx, errors.RecordNotFound, op, "unable to find credential store for provided library")
		return res
	}

	opts = append(opts, auth.WithPin(parentId))

	switch subtypes.SubtypeFromId(domain, parentId) {
	case vault.Subtype:
		cs, err := repo.LookupCredentialStore(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if cs == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		opts = append(opts, auth.WithScopeId(cs.GetProjectId()))
	default:
		res.Error = errors.New(ctx, errors.InvalidParameter, op, "unrecognized credential store subtype from id")
		return res
	}

	return auth.Verify(ctx, opts...)
}

func toProto(in credential.Library, opt ...handlers.Option) (*pb.CredentialLibrary, error) {
	const op = "credentiallibraries.toProto"

	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building credential library proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.CredentialLibrary{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.CredentialStoreIdField) {
		out.CredentialStoreId = in.GetStoreId()
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
	switch subtypes.SubtypeFromId(domain, in.GetPublicId()) {
	case vault.Subtype:
		vaultIn, ok := in.(*vault.CredentialLibrary)
		if !ok {
			return nil, errors.NewDeprecated(errors.Internal, op, "unable to cast to vault credential library")
		}

		if outputFields.Has(globals.CredentialTypeField) && vaultIn.GetCredentialType() != string(credential.UnspecifiedType) {
			out.CredentialType = vaultIn.GetCredentialType()
			if outputFields.Has(globals.CredentialMappingOverridesField) && vaultIn.MappingOverride != nil {
				m := make(map[string]interface{})
				switch mapping := vaultIn.MappingOverride.(type) {
				case *vault.UsernamePasswordOverride:
					if mapping.UsernameAttribute != "" {
						m[usernameAttribute] = mapping.UsernameAttribute
					}
					if mapping.PasswordAttribute != "" {
						m[passwordAttribute] = mapping.PasswordAttribute
					}

				case *vault.SshPrivateKeyOverride:
					if mapping.UsernameAttribute != "" {
						m[usernameAttribute] = mapping.UsernameAttribute
					}
					if mapping.PrivateKeyAttribute != "" {
						m[privateKeyAttribute] = mapping.PrivateKeyAttribute
					}
					if mapping.PrivateKeyPassphraseAttribute != "" {
						m[pkPassphraseAttribute] = mapping.PrivateKeyPassphraseAttribute
					}
				}
				if len(m) > 0 {
					mp, err := structpb.NewStruct(m)
					if err != nil {
						return nil, errors.NewDeprecated(errors.Internal, op, "creating proto struct for mapping override")
					}
					out.CredentialMappingOverrides = mp
				}
			}
		}
		if outputFields.Has(globals.AttributesField) {
			attrs := &pb.VaultCredentialLibraryAttributes{
				Path: wrapperspb.String(vaultIn.GetVaultPath()),
			}
			if vaultIn.GetHttpMethod() != "" {
				attrs.HttpMethod = wrapperspb.String(vaultIn.GetHttpMethod())
			}
			if vaultIn.GetHttpRequestBody() != nil {
				attrs.HttpRequestBody = wrapperspb.String(string(vaultIn.GetHttpRequestBody()))
			}
			out.Attrs = &pb.CredentialLibrary_VaultCredentialLibraryAttributes{
				VaultCredentialLibraryAttributes: attrs,
			}
		}
	}
	return &out, nil
}

func toStorageVaultLibrary(storeId string, in *pb.CredentialLibrary) (out *vault.CredentialLibrary, err error) {
	const op = "credentiallibraries.toStorageVaultLibrary"
	var opts []vault.Option
	if in.GetName() != nil {
		opts = append(opts, vault.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, vault.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetVaultCredentialLibraryAttributes()
	if attrs.GetHttpMethod() != nil {
		opts = append(opts, vault.WithMethod(vault.Method(strings.ToUpper(attrs.GetHttpMethod().GetValue()))))
	}
	if attrs.GetHttpRequestBody() != nil {
		opts = append(opts, vault.WithRequestBody([]byte(attrs.GetHttpRequestBody().GetValue())))
	}

	credentialType := credential.Type(in.GetCredentialType())
	switch credentialType {
	case credential.UsernamePasswordType:
		opts = append(opts, vault.WithCredentialType(credentialType))
		overrides := in.CredentialMappingOverrides.AsMap()
		var mapOpts []vault.Option
		if username := overrides[usernameAttribute]; username != nil {
			mapOpts = append(mapOpts, vault.WithOverrideUsernameAttribute(username.(string)))
		}
		if password := overrides[passwordAttribute]; password != nil {
			mapOpts = append(mapOpts, vault.WithOverridePasswordAttribute(password.(string)))
		}
		if len(mapOpts) > 0 {
			opts = append(opts, vault.WithMappingOverride(vault.NewUsernamePasswordOverride(mapOpts...)))
		}

	case credential.SshPrivateKeyType:
		opts = append(opts, vault.WithCredentialType(credentialType))
		overrides := in.CredentialMappingOverrides.AsMap()
		var mapOpts []vault.Option
		if username := overrides[usernameAttribute]; username != nil {
			mapOpts = append(mapOpts, vault.WithOverrideUsernameAttribute(username.(string)))
		}
		if pk := overrides[privateKeyAttribute]; pk != nil {
			mapOpts = append(mapOpts, vault.WithOverridePrivateKeyAttribute(pk.(string)))
		}
		if pass := overrides[pkPassphraseAttribute]; pass != nil {
			mapOpts = append(mapOpts, vault.WithOverridePrivateKeyPassphraseAttribute(pass.(string)))
		}
		if len(mapOpts) > 0 {
			opts = append(opts, vault.WithMappingOverride(vault.NewSshPrivateKeyOverride(mapOpts...)))
		}
	}

	cs, err := vault.NewCredentialLibrary(storeId, attrs.GetPath().GetValue(), opts...)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("unable to build credential library"))
	}
	return cs, err
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetCredentialLibraryRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, vault.CredentialLibraryPrefix)
}

func validateCreateRequest(req *pbs.CreateCredentialLibraryRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetItem().GetCredentialStoreId()) {
		case vault.Subtype:
			if t := req.GetItem().GetType(); t != "" && subtypes.SubtypeFromType(domain, t) != vault.Subtype {
				badFields[globals.CredentialStoreIdField] = "If included, type must match that of the credential store."
			}
			attrs := req.GetItem().GetVaultCredentialLibraryAttributes()
			if attrs == nil {
				badFields[attributesPathField] = "This is a required field."
			}
			if attrs.GetPath().GetValue() == "" {
				badFields[vaultPathField] = "This is a required field."
			}
			if m := attrs.GetHttpMethod(); m != nil && !strutil.StrListContains([]string{"GET", "POST"}, strings.ToUpper(m.GetValue())) {
				badFields[httpMethodField] = "If set, value must be 'GET' or 'POST'."
			}
			if b := attrs.GetHttpRequestBody(); b != nil && strings.ToUpper(attrs.GetHttpMethod().GetValue()) != "POST" {
				badFields[httpRequestBodyField] = fmt.Sprintf("Field can only be set if %q is set to the value 'POST'.", httpMethodField)
			}
			validateMapping(badFields, credential.Type(req.GetItem().GetCredentialType()), req.GetItem().CredentialMappingOverrides.AsMap())
		default:
			badFields[globals.CredentialStoreIdField] = "This field must be a valid credential store id."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateCredentialLibraryRequest, currentCredentialType credential.Type) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case vault.Subtype:
			if req.GetItem().GetType() != "" && subtypes.SubtypeFromType(domain, req.GetItem().GetType()) != vault.Subtype {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			if req.GetItem().GetCredentialType() != "" && req.GetItem().GetCredentialType() != string(currentCredentialType) {
				badFields[globals.CredentialTypeField] = "Cannot modify credential type."
			}
			attrs := req.GetItem().GetVaultCredentialLibraryAttributes()
			if attrs != nil {
				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), vaultPathField) && attrs.GetPath().GetValue() == "" {
					badFields[vaultPathField] = "This is a required field and cannot be set to empty."
				}
				if m := attrs.GetHttpMethod(); handlers.MaskContains(req.GetUpdateMask().GetPaths(), httpMethodField) && m != nil && !strutil.StrListContains([]string{"GET", "POST"}, strings.ToUpper(m.GetValue())) {
					badFields[httpMethodField] = "If set, value must be 'GET' or 'POST'."
				}
				if b := attrs.GetHttpRequestBody(); b != nil && strings.ToUpper(attrs.GetHttpMethod().GetValue()) == "GET" {
					badFields[httpRequestBodyField] = fmt.Sprintf("Field can only be set if %q is set to the value 'POST'.", httpMethodField)
				}
				validateMapping(badFields, currentCredentialType, req.GetItem().CredentialMappingOverrides.AsMap())
			}
		}
		return badFields
	}, vault.CredentialLibraryPrefix)
}

func validateDeleteRequest(req *pbs.DeleteCredentialLibraryRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, vault.CredentialLibraryPrefix)
}

func validateListRequest(req *pbs.ListCredentialLibrariesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetCredentialStoreId()), vault.CredentialStorePrefix) {
		badFields[globals.CredentialStoreIdField] = "This field must be a valid credential store id."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateMapping(badFields map[string]string, credentialType credential.Type, overrides map[string]interface{}) {
	validFields := make(map[string]bool)
	switch credentialType {
	case "", credential.UnspecifiedType:
		if len(overrides) > 0 {
			badFields[globals.CredentialMappingOverridesField] = fmt.Sprintf("This field can only be set if %q is set", globals.CredentialTypeField)
		}
		return
	case credential.UsernamePasswordType:
		validFields[usernameAttribute] = true
		validFields[passwordAttribute] = true
	case credential.SshPrivateKeyType:
		validFields[usernameAttribute] = true
		validFields[privateKeyAttribute] = true
		validFields[pkPassphraseAttribute] = true
	default:
		badFields[globals.CredentialTypeField] = fmt.Sprintf("Unknown credential type %q", credentialType)
		return
	}

	for k, v := range overrides {
		if ok := validFields[k]; !ok {
			badFields[globals.CredentialMappingOverridesField+"."+k] = fmt.Sprintf("Invalid mapping override for credential type %q", credentialType)
			continue
		}
		if _, ok := v.(string); v != nil && !ok {
			badFields[globals.CredentialMappingOverridesField+"."+k] = fmt.Sprintf("Mapping value must be a string or a null to clear, got %T", v)
		}
	}
}

func getMappingUpdates(credentialType credential.Type, current vault.MappingOverride, new map[string]interface{}, apiMasks []string) (map[string]interface{}, bool) {
	ret := make(map[string]interface{})
	masks := make(map[string]bool)
	for _, m := range apiMasks {
		if m == credentialMappingPathField {
			// got top level credential mapping change request, this mask
			// can only be provided when clearing the entire override.
			return nil, true
		}

		credMappingPrefix := fmt.Sprintf("%v.", credentialMappingPathField)
		if s := strings.SplitN(m, credMappingPrefix, 2); len(s) == 2 {
			masks[s[1]] = true
		}
	}
	if len(masks) == 0 {
		// no mapping updates
		return nil, false
	}

	switch credentialType {
	case credential.UsernamePasswordType:
		var currentUser, currentPass interface{}
		if overrides, ok := current.(*vault.UsernamePasswordOverride); ok {
			currentUser = overrides.UsernameAttribute
			currentPass = overrides.PasswordAttribute
		}

		switch {
		case masks[usernameAttribute]:
			ret[usernameAttribute] = new[usernameAttribute]
		default:
			ret[usernameAttribute] = currentUser
		}

		switch {
		case masks[passwordAttribute]:
			ret[passwordAttribute] = new[passwordAttribute]
		default:
			ret[passwordAttribute] = currentPass
		}

	case credential.SshPrivateKeyType:
		var currentUser, currentpPass, currentPk interface{}
		if overrides, ok := current.(*vault.SshPrivateKeyOverride); ok {
			currentUser = overrides.UsernameAttribute
			currentPk = overrides.PrivateKeyAttribute
			currentpPass = overrides.PrivateKeyPassphraseAttribute
		}

		switch {
		case masks[usernameAttribute]:
			ret[usernameAttribute] = new[usernameAttribute]
		default:
			ret[usernameAttribute] = currentUser
		}

		switch {
		case masks[privateKeyAttribute]:
			ret[privateKeyAttribute] = new[privateKeyAttribute]
		default:
			ret[privateKeyAttribute] = currentPk
		}

		switch {
		case masks[pkPassphraseAttribute]:
			ret[pkPassphraseAttribute] = new[pkPassphraseAttribute]
		default:
			ret[pkPassphraseAttribute] = currentpPass
		}
	}

	return ret, true
}
