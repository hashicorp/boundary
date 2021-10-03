package credentiallibraries

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/servers/controller/auth"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentiallibraries"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	vaultPathField       = "attributes.path"
	httpMethodField      = "attributes.http_method"
	httpRequestBodyField = "attributes.http_request_body"
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
	pbs.UnimplementedCredentialLibraryServiceServer

	iamRepoFn common.IamRepoFactory
	repoFn    common.VaultCredentialRepoFactory
}

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

var _ pbs.CredentialLibraryServiceServer = Service{}

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

		outputFields := authResults.FetchOutputFields(res, action.List).SelfOrDefaults(authResults.UserId)
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

		if filter.Match(item) {
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

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	cl, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
	return &pbs.DeleteCredentialLibraryResponse{}, nil
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

func (s Service) updateInRepo(ctx context.Context, projId, id string, mask []string, item *pb.CredentialLibrary) (credential.Library, error) {
	const op = "credentiallibraries.(Service).updateInRepo"
	cl, err := toStorageVaultLibrary(item.GetCredentialStoreId(), item)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cl.PublicId = id

	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateCredentialLibrary(ctx, projId, cl, item.GetVersion(), dbMask)
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

		switch credential.SubtypeFromId(id) {
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

	switch credential.SubtypeFromId(parentId) {
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
		opts = append(opts, auth.WithScopeId(cs.GetScopeId()))
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
		case vault.Subtype:
			vaultIn, ok := in.(*vault.CredentialLibrary)
			if !ok {
				return nil, errors.NewDeprecated(errors.Internal, op, "unable to cast to vault credential library")
			}
			attrs := &pb.VaultCredentialLibraryAttributes{
				Path: wrapperspb.String(vaultIn.GetVaultPath()),
			}
			if vaultIn.GetHttpMethod() != "" {
				attrs.HttpMethod = wrapperspb.String(vaultIn.GetHttpMethod())
			}
			if vaultIn.GetHttpRequestBody() != nil {
				attrs.HttpRequestBody = wrapperspb.String(string(vaultIn.GetHttpRequestBody()))
			}
			var err error
			out.Attributes, err = handlers.ProtoToStruct(attrs)
			if err != nil {
				return nil, errors.WrapDeprecated(err, op, errors.WithMsg("failed to convert resource from storage to api"))
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

	attrs := &pb.VaultCredentialLibraryAttributes{}
	if err := handlers.StructToProto(in.GetAttributes(), attrs); err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("unable to parse the attributes"))
	}

	if attrs.GetHttpMethod() != nil {
		opts = append(opts, vault.WithMethod(vault.Method(strings.ToUpper(attrs.GetHttpMethod().GetValue()))))
	}
	if attrs.GetHttpRequestBody() != nil {
		opts = append(opts, vault.WithRequestBody([]byte(attrs.GetHttpRequestBody().GetValue())))
	}

	cs, err := vault.NewCredentialLibrary(storeId, attrs.GetPath().GetValue(), opts...)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("unable to build credential library"))
	}
	return cs, err
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetCredentialLibraryRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, vault.CredentialLibraryPrefix)
}

func validateCreateRequest(req *pbs.CreateCredentialLibraryRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch credential.SubtypeFromId(req.GetItem().GetCredentialStoreId()) {
		case vault.Subtype:
			if t := req.GetItem().GetType(); t != "" && credential.SubtypeFromType(t) != vault.Subtype {
				badFields[globals.CredentialStoreIdField] = "If included, type must match that of the credential store."
			}
			attrs := &pb.VaultCredentialLibraryAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[globals.AttributesField] = "Attribute fields do not match the expected format."
				break
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
		default:
			badFields[globals.CredentialStoreIdField] = "This field must be a valid credential store id."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateCredentialLibraryRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch credential.SubtypeFromId(req.GetId()) {
		case vault.Subtype:
			if req.GetItem().GetType() != "" && credential.SubtypeFromType(req.GetItem().GetType()) != vault.Subtype {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			attrs := &pb.VaultCredentialLibraryAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields[globals.AttributesField] = "Attribute fields do not match the expected format."
				break
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), vaultPathField) && attrs.GetPath().GetValue() == "" {
				badFields[vaultPathField] = "This is a required field and cannot be set to empty."
			}
			if m := attrs.GetHttpMethod(); handlers.MaskContains(req.GetUpdateMask().GetPaths(), httpMethodField) && m != nil && !strutil.StrListContains([]string{"GET", "POST"}, strings.ToUpper(m.GetValue())) {
				badFields[httpMethodField] = "If set, value must be 'GET' or 'POST'."
			}
			if b := attrs.GetHttpRequestBody(); b != nil && strings.ToUpper(attrs.GetHttpMethod().GetValue()) == "GET" {
				badFields[httpRequestBodyField] = fmt.Sprintf("Field can only be set if %q is set to the value 'POST'.", httpMethodField)
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
