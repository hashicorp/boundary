package credentials

import (
	"context"
	"encoding/base64"
	"fmt"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/static/store"
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
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/credentials"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	usernameField = "attributes.username"
	passwordField = "attributes.password"
	domain        = "credential"
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
	if maskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.UsernamePasswordCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.UsernamePasswordAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.CredentialServiceServer interface.
type Service struct {
	pbs.UnimplementedCredentialServiceServer

	iamRepoFn common.IamRepoFactory
	repoFn    common.StaticCredentialRepoFactory
}

// NewService returns a credential service which handles credential related requests to boundary.
func NewService(repo common.StaticCredentialRepoFactory, iamRepo common.IamRepoFactory) (Service, error) {
	const op = "credentials.NewService"
	if iamRepo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing iam repository")
	}
	if repo == nil {
		return Service{}, errors.NewDeprecated(errors.InvalidParameter, op, "missing static credential repository")
	}
	return Service{iamRepoFn: iamRepo, repoFn: repo}, nil
}

var _ pbs.CredentialServiceServer = Service{}

// ListCredentials implements the interface pbs.CredentialServiceServer
func (s Service) ListCredentials(ctx context.Context, req *pbs.ListCredentialsRequest) (*pbs.ListCredentialsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetCredentialStoreId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}

	creds, err := s.listFromRepo(ctx, req.GetCredentialStoreId())
	if err != nil {
		return nil, err
	}
	if len(creds) == 0 {
		return &pbs.ListCredentialsResponse{}, nil
	}

	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Credential, 0, len(creds))
	res := perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.Credential,
		Pin:     req.GetCredentialStoreId(),
	}
	for _, item := range creds {
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

		filterable, err := subtypes.Filterable(item)
		if err != nil {
			return nil, err
		}
		if filter.Match(filterable) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListCredentialsResponse{Items: finalItems}, nil
}

// GetCredential implements the interface pbs.CredentialServiceServer.
func (s Service) GetCredential(ctx context.Context, req *pbs.GetCredentialRequest) (*pbs.GetCredentialResponse, error) {
	const op = "credentials.(Service).GetCredential"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	c, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, c.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(c, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetCredentialResponse{Item: item}, nil
}

// CreateCredential implements the interface pbs.CredentialServiceServer.
func (s Service) CreateCredential(ctx context.Context, req *pbs.CreateCredentialRequest) (*pbs.CreateCredentialResponse, error) {
	const op = "credentials.(Service).CreateCredential"

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

	return &pbs.CreateCredentialResponse{
		Item: item,
		Uri:  fmt.Sprintf("credentials/%s", item.GetId()),
	}, nil
}

// UpdateCredential implements the interface pbs.CredentialServiceServer.
func (s Service) UpdateCredential(ctx context.Context, req *pbs.UpdateCredentialRequest) (*pbs.UpdateCredentialResponse, error) {
	const op = "credentials.(Service).UpdateCredential"

	cur, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	storeId := cur.GetStoreId()

	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	c, err := s.updateInRepo(ctx, authResults.Scope.GetId(), storeId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, c.GetPublicId(), IdActions).Strings()))
	}

	item, err := toProto(c, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateCredentialResponse{Item: item}, nil
}

// DeleteCredential implements the interface pbs.CredentialServiceServer.
func (s Service) DeleteCredential(ctx context.Context, req *pbs.DeleteCredentialRequest) (*pbs.DeleteCredentialResponse, error) {
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

func (s Service) listFromRepo(ctx context.Context, storeId string) ([]credential.Static, error) {
	const op = "credentials.(Service).listFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	up, err := repo.ListCredentials(ctx, storeId)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	creds := make([]credential.Static, 0, len(up))
	for _, s := range up {
		creds = append(creds, s)
	}

	return creds, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (credential.Static, error) {
	const op = "credentials.(Service).getFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cred, err := repo.LookupCredential(ctx, id)
	if err != nil && !errors.IsNotFoundError(err) {
		return nil, errors.Wrap(ctx, err, op)
	}
	if cred == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, fmt.Sprintf("credential %q not found", id))
	}
	return cred, err
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Credential) (credential.Static, error) {
	const op = "credentials.(Service).createInRepo"
	switch item.GetType() {
	case static.UsernamePasswordSubtype.String():
		cred, err := toUsernamePasswordStorageCredential(item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, err := repo.CreateUsernamePasswordCredential(ctx, scopeId, cred)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create credential"))
		}
		if out == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create credential but no error returned from repository.")
		}
		return out, nil
	default:
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, fmt.Sprintf("Unsupported credential type %q", item.GetType()))
	}
}

func (s Service) updateInRepo(
	ctx context.Context,
	scopeId, storeId, id string,
	masks []string,
	in *pb.Credential,
) (credential.Static, error) {
	const op = "credentials.(Service).updateInRepo"

	var dbMasks []string
	item := proto.Clone(in).(*pb.Credential)

	dbMasks = append(dbMasks, maskManager.Translate(masks)...)
	if len(dbMasks) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}

	switch subtypes.SubtypeFromId(domain, id) {
	case static.UsernamePasswordSubtype:
		cred, err := toUsernamePasswordStorageCredential(storeId, in)
		cred.PublicId = id
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, rowsUpdated, err := repo.UpdateUsernamePasswordCredential(ctx, scopeId, cred, item.GetVersion(), dbMasks)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential"))
		}
		if rowsUpdated == 0 {
			return nil, handlers.NotFoundErrorf("Credential %q doesn't exist or incorrect version provided.", id)
		}
		return out, nil
	default:
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, fmt.Sprintf("Unsupported credential type %q", item.GetType()))

	}
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "credentials.(Service).deleteFromRepo"
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}

	rows, err := repo.DeleteCredential(ctx, scopeId, id)
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete credential"))
	}
	return rows > 0, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	const op = "credentials.(Service).authResult"
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Credential), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		opts = append(opts, auth.WithId(id))
		cred, err := repo.LookupCredential(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if cred == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = cred.GetStoreId()

	}

	if parentId == "" {
		res.Error = errors.New(ctx, errors.RecordNotFound, op, "unable to find credential store for provided credential")
		return res
	}
	opts = append(opts, auth.WithPin(parentId))

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

	return auth.Verify(ctx, opts...)
}

func toProto(in credential.Static, opt ...handlers.Option) (*pb.Credential, error) {
	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building credential proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Credential{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.CredentialStoreIdField) {
		out.CredentialStoreId = in.GetStoreId()
	}
	if outputFields.Has(globals.TypeField) {
		switch in.(type) {
		case *static.UsernamePasswordCredential:
			out.Type = static.UsernamePasswordSubtype.String()
		}
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

	switch cred := in.(type) {
	case *static.UsernamePasswordCredential:
		if outputFields.Has(globals.AttributesField) {
			out.Attrs = &pb.Credential_UsernamePasswordAttributes{
				UsernamePasswordAttributes: &pb.UsernamePasswordAttributes{
					Username:     wrapperspb.String(cred.GetUsername()),
					PasswordHmac: base64.RawURLEncoding.EncodeToString(cred.GetPasswordHmac()),
				},
			}
		}
	}
	return &out, nil
}

func toUsernamePasswordStorageCredential(storeId string, in *pb.Credential) (out *static.UsernamePasswordCredential, err error) {
	const op = "credentials.toStorageCredential"
	var opts []static.Option
	if in.GetName() != nil {
		opts = append(opts, static.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, static.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetUsernamePasswordAttributes()
	cs, err := static.NewUsernamePasswordCredential(
		storeId,
		attrs.GetUsername().GetValue(),
		credential.Password(attrs.GetPassword().GetValue()),
		opts...)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("unable to build credential"))
	}

	return cs, err
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetCredentialRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, static.CredentialPrefix)
}

func validateCreateRequest(req *pbs.CreateCredentialRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.Item.GetType() != static.UsernamePasswordSubtype.String() {
			badFields[globals.TypeField] = fmt.Sprintf("Unsupported credential type %q", req.Item.GetType())
		}
		if !handlers.ValidId(handlers.Id(req.Item.GetCredentialStoreId()), static.CredentialStorePrefix) {
			badFields[globals.CredentialStoreIdField] = "This field must be a valid credential store id."
		}

		if req.Item.GetUsernamePasswordAttributes().GetUsername().GetValue() == "" {
			badFields[usernameField] = "Field required for creating a username-password credential."
		}
		if req.Item.GetUsernamePasswordAttributes().GetPassword().GetValue() == "" {
			badFields[passwordField] = "Field required for creating a username-password credential."
		}

		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateCredentialRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetType() != "" && req.GetItem().GetType() != static.UsernamePasswordSubtype.String() {
			badFields[globals.TypeField] = "Cannot modify resource type."
		}

		attrs := req.GetItem().GetUsernamePasswordAttributes()
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), usernameField) && attrs.GetUsername().GetValue() == "" {
			badFields[usernameField] = "This is a required field and cannot be set to empty."
		}
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), passwordField) && attrs.GetPassword().GetValue() == "" {
			badFields[passwordField] = "This is a required field and cannot be set to empty."
		}

		return badFields
	}, static.CredentialPrefix)
}

func validateDeleteRequest(req *pbs.DeleteCredentialRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, static.CredentialPrefix)
}

func validateListRequest(req *pbs.ListCredentialsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetCredentialStoreId()), static.CredentialStorePrefix) {
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
