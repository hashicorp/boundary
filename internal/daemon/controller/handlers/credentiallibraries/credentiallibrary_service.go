// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package credentiallibraries

import (
	"context"
	"encoding/json"
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
	"github.com/hashicorp/boundary/version"
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
	sshCertUsernameField       = "attributes.username"
	keyTypeField               = "attributes.key_type"
	keyBitsField               = "attributes.key_bits"
	criticalOptionsField       = "attributes.critical_options"
	extensionsField            = "attributes.extensions"
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
	maskManager        handlers.MaskManager
	sshCertMaskManager handlers.MaskManager

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

	validCredentialTypesVaultGeneric = []credential.Type{
		credential.UsernamePasswordType,
		credential.SshPrivateKeyType,
		credential.UnspecifiedType,
	}

	validKeyTypes = []string{
		vault.KeyTypeEcdsa,
		vault.KeyTypeEd25519,
		vault.KeyTypeRsa,
	}
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.CredentialLibrary{}},
		handlers.MaskSource{&pb.CredentialLibrary{}, &pb.VaultCredentialLibraryAttributes{}},
	); err != nil {
		panic(err)
	}
	if sshCertMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.SSHCertificateCredentialLibrary{}},
		handlers.MaskSource{&pb.CredentialLibrary{}, &pb.VaultSSHCertificateCredentialLibraryAttributes{}},
	); err != nil {
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
func NewService(ctx context.Context, repo common.VaultCredentialRepoFactory, iamRepo common.IamRepoFactory) (Service, error) {
	const op = "credentiallibraries.NewService"
	if iamRepo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing vault credential repository")
	}
	return Service{iamRepoFn: iamRepo, repoFn: repo}, nil
}

// ListCredentialLibraries implements the interface pbs.CredentialLibraryServiceServer
func (s Service) ListCredentialLibraries(ctx context.Context, req *pbs.ListCredentialLibrariesRequest) (*pbs.ListCredentialLibrariesResponse, error) {
	if err := validateListRequest(ctx, req); err != nil {
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

	filter, err := handlers.NewFilter(ctx, req.GetFilter())
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
		outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
		if outputFields.Has(globals.ScopeField) {
			outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
		}
		if outputFields.Has(globals.AuthorizedActionsField) {
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cs.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, cs, outputOpts...)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
	if outputFields.Has(globals.ScopeField) {
		outputOpts = append(outputOpts, handlers.WithScope(authResults.Scope))
	}
	if outputFields.Has(globals.AuthorizedActionsField) {
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cl.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, cl, outputOpts...)
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
	var currentCredentialType credential.Type
	var mo vault.MappingOverride
	switch subtypes.SubtypeFromId(domain, req.GetId()) {
	case vault.SSHCertificateLibrarySubtype:
		cur, err := repo.LookupSSHCertificateCredentialLibrary(ctx, req.Id)
		if err != nil {
			return nil, err
		}
		currentCredentialType = credential.Type(cur.GetCredentialType())
	default:
		cur, err := repo.LookupCredentialLibrary(ctx, req.Id)
		if err != nil {
			return nil, err
		}
		currentCredentialType = credential.Type(cur.GetCredentialType())
		mo = cur.MappingOverride
	}

	if err := validateUpdateRequest(req, currentCredentialType); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	cl, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem(), currentCredentialType, mo)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, cl.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(ctx, cl, outputOpts...)
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

func (s Service) listFromRepo(ctx context.Context, storeId string) ([]credential.Library, error) {
	const op = "credentiallibraries.(Service).listFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	genCsl, err := repo.ListCredentialLibraries(ctx, storeId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	certCsl, err := repo.ListSSHCertificateCredentialLibraries(ctx, storeId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	csl := make([]credential.Library, 0, len(genCsl)+len(certCsl))
	for _, s := range genCsl {
		csl = append(csl, s)
	}
	for _, s := range certCsl {
		csl = append(csl, s)
	}
	return csl, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (credential.Library, error) {
	const op = "credentiallibraries.(Service).getFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch subtypes.SubtypeFromId(domain, id) {
	case vault.GenericLibrarySubtype:
		cs, err := repo.LookupCredentialLibrary(ctx, id)
		if err != nil && !errors.IsNotFoundError(err) {
			return nil, errors.Wrap(ctx, err, op)
		}
		if cs == nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("credential library %q not found", id))
		}
		return cs, err
	case vault.SSHCertificateLibrarySubtype:
		cs, err := repo.LookupSSHCertificateCredentialLibrary(ctx, id)
		if err != nil && !errors.IsNotFoundError(err) {
			return nil, errors.Wrap(ctx, err, op)
		}
		if cs == nil {
			return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("ssh certificate credential library %q not found", id))
		}
		return cs, err
	}
	return nil, errors.New(ctx, errors.InvalidParameter, op, "unrecognized credential library subtype")
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.CredentialLibrary) (credential.Library, error) {
	const op = "credentiallibraries.(Service).createInRepo"
	var out credential.Library
	switch subtypes.SubtypeFromType(domain, item.GetType()) {
	case vault.SSHCertificateLibrarySubtype:
		cl, err := toStorageVaultSSHCertificateLibrary(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		rl, err := repo.CreateSSHCertificateCredentialLibrary(ctx, scopeId, cl)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create ssh certificate credential library"))
		}
		if rl == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create ssh certificate credential library but no error returned from repository.")
		}
		out = rl
	default:
		cl, err := toStorageVaultLibrary(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		rl, err := repo.CreateCredentialLibrary(ctx, scopeId, cl)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create credential library"))
		}
		if rl == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create credential library but no error returned from repository.")
		}
		out = rl
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

	var out credential.Library
	rowsUpdated := 0
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	switch subtypes.SubtypeFromId(domain, id) {
	case vault.SSHCertificateLibrarySubtype:
		dbMasks = append(dbMasks, sshCertMaskManager.Translate(masks)...)
		if getMapUpdate(criticalOptionsField, masks) {
			dbMasks = append(dbMasks, vault.CriticalOptionsField)
		}
		if getMapUpdate(extensionsField, masks) {
			dbMasks = append(dbMasks, vault.ExtensionsField)
		}
		if len(dbMasks) == 0 {
			return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
		}
		cl, err := toStorageVaultSSHCertificateLibrary(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cl.PublicId = id
		out, rowsUpdated, err = repo.UpdateSSHCertificateCredentialLibrary(ctx, projId, cl, item.GetVersion(), dbMasks)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential library"))
		}
		if rowsUpdated == 0 {
			return nil, handlers.NotFoundErrorf("Credential Library %q doesn't exist or incorrect version provided.", id)
		}
	default:
		dbMasks = append(dbMasks, maskManager.Translate(masks)...)
		if len(dbMasks) == 0 {
			return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
		}
		cl, err := toStorageVaultLibrary(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		cl.PublicId = id
		out, rowsUpdated, err = repo.UpdateCredentialLibrary(ctx, projId, cl, item.GetVersion(), dbMasks)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential library"))
		}
		if rowsUpdated == 0 {
			return nil, handlers.NotFoundErrorf("Credential Library %q doesn't exist or incorrect version provided.", id)
		}
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "credentiallibraries.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows := 0
	switch subtypes.SubtypeFromId(domain, id) {
	case vault.SSHCertificateLibrarySubtype:
		rows, err = repo.DeleteSSHCertificateCredentialLibrary(ctx, scopeId, id)
	default:
		rows, err = repo.DeleteCredentialLibrary(ctx, scopeId, id)
	}
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
		parentId = id
		switch subtypes.SubtypeFromId(domain, id) {
		case vault.GenericLibrarySubtype:
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
		case vault.SSHCertificateLibrarySubtype:
			cl, err := repo.LookupSSHCertificateCredentialLibrary(ctx, id)
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

func toProto(ctx context.Context, in credential.Library, opt ...handlers.Option) (*pb.CredentialLibrary, error) {
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
	case vault.GenericLibrarySubtype:
		vaultIn, ok := in.(*vault.CredentialLibrary)
		if !ok {
			return nil, errors.New(ctx, errors.Internal, op, "unable to cast to vault credential library")
		}

		if outputFields.Has(globals.CredentialTypeField) && vaultIn.GetCredentialType() != string(credential.UnspecifiedType) {
			out.CredentialType = vaultIn.GetCredentialType()
			if outputFields.Has(globals.CredentialMappingOverridesField) && vaultIn.MappingOverride != nil {
				m := make(map[string]any)
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
						return nil, errors.New(ctx, errors.Internal, op, "creating proto struct for mapping override")
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
			out.Attrs = &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
				VaultGenericCredentialLibraryAttributes: attrs,
			}
		}
	case vault.SSHCertificateLibrarySubtype:
		vaultIn, ok := in.(*vault.SSHCertificateCredentialLibrary)
		if !ok {
			return nil, errors.New(ctx, errors.Internal, op, "unable to cast to vault ssh certificate credential library")
		}
		// We don't check for mapping overrides here -- this subtype does not currently support them.
		out.CredentialType = vaultIn.GetCredentialType()
		if outputFields.Has(globals.AttributesField) {
			attrs := &pb.VaultSSHCertificateCredentialLibraryAttributes{
				Path: wrapperspb.String(vaultIn.GetVaultPath()),
			}
			if vaultIn.GetUsername() != "" {
				attrs.Username = wrapperspb.String(vaultIn.GetUsername())
			}
			if vaultIn.GetKeyType() != "" {
				attrs.KeyType = wrapperspb.String(vaultIn.GetKeyType())
			}
			if vaultIn.GetKeyBits() != 0 {
				attrs.KeyBits = &wrapperspb.UInt32Value{Value: vaultIn.GetKeyBits()}
			}
			if vaultIn.GetTtl() != "" {
				attrs.Ttl = wrapperspb.String(vaultIn.GetTtl())
			}
			if vaultIn.GetKeyId() != "" {
				attrs.KeyId = wrapperspb.String(vaultIn.GetKeyId())
			}
			if vaultIn.GetCriticalOptions() != "" {
				co := make(map[string]string)
				json.Unmarshal([]byte(vaultIn.GetCriticalOptions()), &co)
				attrs.CriticalOptions = co
			}
			if vaultIn.GetExtensions() != "" {
				e := make(map[string]string)
				json.Unmarshal([]byte(vaultIn.GetExtensions()), &e)
				attrs.Extensions = e
			}
			out.Attrs = &pb.CredentialLibrary_VaultSshCertificateCredentialLibraryAttributes{
				VaultSshCertificateCredentialLibraryAttributes: attrs,
			}
		}

	}
	return &out, nil
}

func toStorageVaultLibrary(ctx context.Context, storeId string, in *pb.CredentialLibrary) (out *vault.CredentialLibrary, err error) {
	const op = "credentiallibraries.toStorageVaultLibrary"
	var opts []vault.Option
	if in.GetName() != nil {
		opts = append(opts, vault.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, vault.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetVaultGenericCredentialLibraryAttributes()
	if attrs == nil {
		// fallback to attributes for older subtype
		attrs = in.GetVaultCredentialLibraryAttributes()
	}
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
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential library"))
	}
	return cs, err
}

func toStorageVaultSSHCertificateLibrary(ctx context.Context, storeId string, in *pb.CredentialLibrary) (out *vault.SSHCertificateCredentialLibrary, err error) {
	const op = "credentiallibraries.toStorageVaultSSHCertificateLibrary"
	var opts []vault.Option
	if in.GetName() != nil {
		opts = append(opts, vault.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, vault.WithDescription(in.GetDescription().GetValue()))
	}
	opts = append(opts, vault.WithCredentialType(credential.Type(in.GetCredentialType())))

	attrs := in.GetVaultSshCertificateCredentialLibraryAttributes()
	if attrs.GetKeyType() != nil {
		opts = append(opts, vault.WithKeyType(attrs.GetKeyType().GetValue()))
	}
	if attrs.GetKeyBits() != nil {
		opts = append(opts, vault.WithKeyBits(attrs.GetKeyBits().GetValue()))
	}
	if attrs.GetTtl() != nil {
		opts = append(opts, vault.WithTtl(attrs.GetTtl().GetValue()))
	}
	if attrs.GetKeyId() != nil {
		opts = append(opts, vault.WithKeyId(attrs.GetKeyId().GetValue()))
	}
	if attrs.GetCriticalOptions() != nil {
		co, err := json.Marshal(attrs.GetCriticalOptions())
		if err != nil {
			return nil, err
		}
		opts = append(opts, vault.WithCriticalOptions(string(co)))
	}
	if attrs.GetExtensions() != nil {
		e, err := json.Marshal(attrs.GetExtensions())
		if err != nil {
			return nil, err
		}
		opts = append(opts, vault.WithExtensions(string(e)))
	}

	cs, err := vault.NewSSHCertificateCredentialLibrary(storeId, attrs.GetPath().GetValue(), attrs.GetUsername().GetValue(), opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential library"))
	}
	return cs, err
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetCredentialLibraryRequest) error {
	prefix := ""
	switch subtypes.SubtypeFromId(domain, req.GetId()) {
	case vault.SSHCertificateLibrarySubtype:
		prefix = globals.VaultSshCertificateCredentialLibraryPrefix
	default:
		prefix = globals.VaultCredentialLibraryPrefix
	}
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, prefix)
}

func validateCreateRequest(req *pbs.CreateCredentialLibraryRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetItem().GetCredentialStoreId()) {
		case vault.Subtype:
			var t string
			if version.SupportsFeature(version.Binary, version.CredentialLibraryVaultSubtype) {
				t = req.GetItem().GetType()

				// To support older cli's that do not send a `type`, assume
				// subtype of vault-generic based on the credential store's subtype.
				// To support the deprecated subtype 'vault.Subtype', convert it
				// to vault-generic.
				if t == "" || subtypes.SubtypeFromType(domain, t) == vault.Subtype {
					// fallback to assuming subtype from credential store.
					t = vault.GenericLibrarySubtype.String()
					req.GetItem().Type = t

					switch req.GetItem().Attrs.(type) {
					case *pb.CredentialLibrary_Attributes:
						oldAttrs := req.GetItem().GetAttributes()
						newAttrs := &pb.VaultCredentialLibraryAttributes{}
						_ = handlers.StructToProto(oldAttrs, newAttrs)
						req.GetItem().Attrs = &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
							VaultGenericCredentialLibraryAttributes: newAttrs,
						}
					case *pb.CredentialLibrary_VaultCredentialLibraryAttributes:
						req.GetItem().Attrs = &pb.CredentialLibrary_VaultGenericCredentialLibraryAttributes{
							VaultGenericCredentialLibraryAttributes: req.GetItem().GetVaultCredentialLibraryAttributes(),
						}
					}
				}
			} else {
				t = req.GetItem().GetType()
				if t == "" {
					badFields[globals.TypeField] = "This is a required field."
				}
			}

			if subtypes.SubtypeFromType(domain, t) != vault.GenericLibrarySubtype &&
				subtypes.SubtypeFromType(domain, t) != vault.SSHCertificateLibrarySubtype {
				badFields[globals.CredentialStoreIdField] = fmt.Sprintf("Type must be a vault subtype %q or %q", vault.GenericLibrarySubtype.String(), vault.SSHCertificateLibrarySubtype.String())
			}

			switch subtypes.SubtypeFromType(domain, req.GetItem().GetType()) {
			case vault.GenericLibrarySubtype:
				isValidCred := false
				ct := req.GetItem().GetCredentialType()
				for _, t := range validCredentialTypesVaultGeneric {
					if ct == "" || ct == string(t) {
						isValidCred = true
						break
					}
				}
				if !isValidCred {
					badFields[globals.CredentialTypeField] = fmt.Sprintf("Unknown credential type %q", ct)
				}

				attrs := req.GetItem().GetVaultGenericCredentialLibraryAttributes()
				if attrs == nil {
					// fallback to attributes for older subtype
					attrs = req.GetItem().GetVaultCredentialLibraryAttributes()
					if attrs == nil {
						badFields[attributesPathField] = "This is a required field."
					}
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
			case vault.SSHCertificateLibrarySubtype:
				if req.GetItem().GetCredentialType() != "" {
					badFields[globals.CredentialTypeField] = fmt.Sprintf("This field is read only and cannot be set.")
				}

				attrs := req.GetItem().GetVaultSshCertificateCredentialLibraryAttributes()
				if attrs == nil {
					badFields[attributesPathField] = "This is a required field."
				}
				if attrs.GetPath().GetValue() == "" {
					badFields[vaultPathField] = "This is a required field."
				}
				if attrs.GetUsername().GetValue() == "" {
					badFields[sshCertUsernameField] = "This is a required field."
				}
				if (attrs.GetKeyType() == nil) != (attrs.GetKeyBits() == nil) {
					if attrs.GetKeyType() != nil && attrs.GetKeyType().GetValue() != vault.KeyTypeEd25519 {
						badFields[keyTypeField] = fmt.Sprintf("If set, %q must also be set.", keyBitsField)
					}
					if attrs.GetKeyBits() != nil {
						badFields[keyBitsField] = fmt.Sprintf("If set, %q must also be set.", keyTypeField)
					}
				}
				if t := attrs.GetKeyType(); t != nil && !strutil.StrListContains(validKeyTypes, strings.ToLower(t.GetValue())) {
					badFields[keyTypeField] = "If set, value must be 'ed25519', 'ecdsa', or 'rsa'."
				}
				validateKeyBits(badFields, attrs.GetKeyBits().GetValue(), attrs.GetKeyType().GetValue())
			}
		default:
			badFields[globals.CredentialStoreIdField] = "This field must be a valid credential store id."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateCredentialLibraryRequest, currentCredentialType credential.Type) error {
	prefix := ""
	st := subtypes.SubtypeFromId(domain, req.GetId())
	switch st {
	case vault.GenericLibrarySubtype:
		prefix = globals.VaultCredentialLibraryPrefix
	case vault.SSHCertificateLibrarySubtype:
		prefix = globals.VaultSshCertificateCredentialLibraryPrefix
	}
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch st {
		case vault.GenericLibrarySubtype:
			if req.GetItem().GetType() != "" && subtypes.SubtypeFromType(domain, req.GetItem().GetType()) != vault.GenericLibrarySubtype {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			if req.GetItem().GetCredentialType() != "" && req.GetItem().GetCredentialType() != string(currentCredentialType) {
				badFields[globals.CredentialTypeField] = "Cannot modify credential type."
			}
			attrs := req.GetItem().GetVaultGenericCredentialLibraryAttributes()
			if attrs == nil {
				// fallback to attributes for older subtype
				attrs = req.GetItem().GetVaultCredentialLibraryAttributes()
			}
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
		case vault.SSHCertificateLibrarySubtype:
			if req.GetItem().GetType() != "" && subtypes.SubtypeFromType(domain, req.GetItem().GetType()) != vault.SSHCertificateLibrarySubtype {
				badFields[globals.TypeField] = "Cannot modify resource type."
			}
			if req.GetItem().GetCredentialType() != "" && req.GetItem().GetCredentialType() != string(currentCredentialType) {
				badFields[globals.CredentialTypeField] = "Cannot modify credential type."
			}
			attrs := req.GetItem().GetVaultSshCertificateCredentialLibraryAttributes()
			if attrs != nil {
				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), vaultPathField) && attrs.GetPath().GetValue() == "" {
					badFields[vaultPathField] = "This is a required field and cannot be set to empty."
				}
				if u := attrs.GetUsername().GetValue(); handlers.MaskContains(req.GetUpdateMask().GetPaths(), sshCertUsernameField) && u == "" {
					badFields[sshCertUsernameField] = "This is a required field and cannot be set to empty."
				}
				if t := attrs.GetKeyType(); t != nil && !strutil.StrListContains(validKeyTypes, strings.ToLower(t.GetValue())) {
					badFields[keyTypeField] = "If set, value must be 'ed25519', 'ecdsa', or 'rsa'."
				}
				validateKeyBits(badFields, attrs.GetKeyBits().GetValue(), attrs.GetKeyType().GetValue())
			}
		}
		return badFields
	}, prefix)
}

func validateDeleteRequest(req *pbs.DeleteCredentialLibraryRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.VaultCredentialLibraryPrefix, globals.VaultSshCertificateCredentialLibraryPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListCredentialLibrariesRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetCredentialStoreId()), globals.VaultCredentialStorePrefix) {
		badFields[globals.CredentialStoreIdField] = "This field must be a valid credential store id."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateMapping(badFields map[string]string, credentialType credential.Type, overrides map[string]any) {
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

// validateKeyBits appends to badFields if keyBits and keyType aren't accepted combinations for an SSHCertificateCredentialLibrary.
// If keyType is an empty string, validateKeyBits only validates keyBits.
func validateKeyBits(badFields map[string]string, keyBits uint32, keyType string) {
	switch keyBits {
	case vault.KeyBitsDefault:
	case vault.KeyBitsEcdsa256, vault.KeyBitsEcdsa384, vault.KeyBitsEcdsa521:
		if keyType != "" && keyType != vault.KeyTypeEcdsa {
			badFields[keyBitsField] = fmt.Sprintf("Invalid bit size %d for key type %s", keyBits, keyType)
		}
	case vault.KeyBitsRsa2048, vault.KeyBitsRsa3072, vault.KeyBitsRsa4096:
		if keyType != "" && keyType != vault.KeyTypeRsa {
			badFields[keyBitsField] = fmt.Sprintf("Invalid bit size %d for key type %s", keyBits, keyType)
		}
	default:
		badFields[keyBitsField] = fmt.Sprintf("Invalid bit size %d", keyBits)
	}
}

func getMapUpdate(field string, apiMasks []string) bool {
	for _, m := range apiMasks {
		if m == field {
			return true
		}

		fieldPrefix := fmt.Sprintf("%v.", field)
		if s := strings.SplitN(m, fieldPrefix, 2); len(s) == 2 {
			return true
		}
	}
	return false
}

func getMappingUpdates(credentialType credential.Type, current vault.MappingOverride, new map[string]any, apiMasks []string) (map[string]any, bool) {
	ret := make(map[string]any)
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
		var currentUser, currentPass any
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
		var currentUser, currentpPass, currentPk any
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
