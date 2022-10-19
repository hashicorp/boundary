package credentials

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
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
	"golang.org/x/crypto/ssh"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	usernameField             = "attributes.username"
	passwordField             = "attributes.password"
	privateKeyField           = "attributes.private_key"
	privateKeyPassphraseField = "attributes.private_key_passphrase"
	objectField               = "attributes.object"
	domain                    = "credential"
)

var (
	upMaskManager   handlers.MaskManager
	spkMaskManager  handlers.MaskManager
	jsonMaskManager handlers.MaskManager

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
	if upMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.UsernamePasswordCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.UsernamePasswordAttributes{}}); err != nil {
		panic(err)
	}
	if spkMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.SshPrivateKeyCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.SshPrivateKeyAttributes{}}); err != nil {
		panic(err)
	}
	if jsonMaskManager, err = handlers.NewMaskManager(handlers.MaskDestination{&store.JsonCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.JsonAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.CredentialServiceServer interface.
type Service struct {
	pbs.UnsafeCredentialServiceServer

	iamRepoFn common.IamRepoFactory
	repoFn    common.StaticCredentialRepoFactory
}

var _ pbs.CredentialServiceServer = (*Service)(nil)

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
	creds = append(creds, up...)

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
	case credential.UsernamePasswordSubtype.String():
		cred, err := toUsernamePasswordStorageCredential(ctx, item.GetCredentialStoreId(), item)
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
	case credential.SshPrivateKeySubtype.String():
		cred, err := toSshPrivateKeyStorageCredential(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, err := repo.CreateSshPrivateKeyCredential(ctx, scopeId, cred)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create credential"))
		}
		if out == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create credential but no error returned from repository.")
		}
		return out, nil
	case credential.JsonSubtype.String():
		cred, err := toJsonStorageCredential(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, err := repo.CreateJsonCredential(ctx, scopeId, cred)
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

	switch subtypes.SubtypeFromId(domain, id) {
	case credential.UsernamePasswordSubtype:
		dbMasks = append(dbMasks, upMaskManager.Translate(masks)...)
		if len(dbMasks) == 0 {
			return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
		}

		cred, err := toUsernamePasswordStorageCredential(ctx, storeId, in)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert to username/password storage credential"))
		}
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

	case credential.SshPrivateKeySubtype:
		dbMasks = append(dbMasks, spkMaskManager.Translate(masks)...)
		if len(dbMasks) == 0 {
			return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
		}

		cred, err := toSshPrivateKeyStorageCredential(ctx, storeId, in)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert to ssh private key storage credential"))
		}
		if cred.PassphraseUnneeded {
			// This happens when we have a private key given and no passphrase
			// given and everything parses correctly. In that case we want to
			// ensure that if a passphrase was in the database for the previous
			// key that we get rid of it. We'll have nilled out several values
			// above. Note that adding the passphrase field will, once we get to
			// the repo, result in the mask for the other two related fields as
			// well.
			dbMasks = append(dbMasks, static.PrivateKeyPassphraseField)
		}
		cred.PublicId = id
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, rowsUpdated, err := repo.UpdateSshPrivateKeyCredential(ctx, scopeId, cred, item.GetVersion(), dbMasks)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential"))
		}
		if rowsUpdated == 0 {
			return nil, handlers.NotFoundErrorf("Credential %q doesn't exist or incorrect version provided.", id)
		}
		return out, nil

	case credential.JsonSubtype:
		dbMasks = append(dbMasks, jsonMaskManager.Translate(masks, "attributes", "object")...)
		if len(dbMasks) == 0 {
			return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
		}

		cred, err := toJsonStorageCredential(ctx, storeId, in)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert to json storage credential"))
		}
		cred.PublicId = id
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, rowsUpdated, err := repo.UpdateJsonCredential(ctx, scopeId, cred, item.GetVersion(), dbMasks)
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
	opts = append(opts, auth.WithScopeId(cs.GetProjectId()))

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
			out.Type = credential.UsernamePasswordSubtype.String()
		case *static.SshPrivateKeyCredential:
			out.Type = credential.SshPrivateKeySubtype.String()
		case *static.JsonCredential:
			out.Type = credential.JsonSubtype.String()
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
	case *static.SshPrivateKeyCredential:
		if outputFields.Has(globals.AttributesField) {
			out.Attrs = &pb.Credential_SshPrivateKeyAttributes{
				SshPrivateKeyAttributes: &pb.SshPrivateKeyAttributes{
					Username:                 wrapperspb.String(cred.GetUsername()),
					PrivateKeyHmac:           base64.RawURLEncoding.EncodeToString(cred.GetPrivateKeyHmac()),
					PrivateKeyPassphraseHmac: base64.RawURLEncoding.EncodeToString(cred.GetPrivateKeyPassphraseHmac()),
				},
			}
		}
	case *static.JsonCredential:
		if outputFields.Has(globals.AttributesField) {
			out.Attrs = &pb.Credential_JsonAttributes{
				JsonAttributes: &pb.JsonAttributes{
					ObjectHmac: base64.RawURLEncoding.EncodeToString(cred.GetObjectHmac()),
				},
			}
		}
	}
	return &out, nil
}

func toUsernamePasswordStorageCredential(ctx context.Context, storeId string, in *pb.Credential) (out *static.UsernamePasswordCredential, err error) {
	const op = "credentials.toUsernamePasswordStorageCredential"
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
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential"))
	}

	return cs, err
}

func toSshPrivateKeyStorageCredential(ctx context.Context, storeId string, in *pb.Credential) (out *static.SshPrivateKeyCredential, err error) {
	const op = "credentials.toSshPrivateKeyStorageCredential"
	var opts []static.Option
	if in.GetName() != nil {
		opts = append(opts, static.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, static.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetSshPrivateKeyAttributes()
	if attrs.GetPrivateKeyPassphrase() != nil {
		opts = append(opts, static.WithPrivateKeyPassphrase([]byte(attrs.GetPrivateKeyPassphrase().GetValue())))
	}
	cs, err := static.NewSshPrivateKeyCredential(
		ctx,
		storeId,
		attrs.GetUsername().GetValue(),
		credential.PrivateKey(attrs.GetPrivateKey().GetValue()),
		opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential"))
	}

	return cs, err
}

func toJsonStorageCredential(ctx context.Context, storeId string, in *pb.Credential) (out *static.JsonCredential, err error) {
	const op = "credentials.toJsonStorageCredential"
	var opts []static.Option
	if in.GetName() != nil {
		opts = append(opts, static.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, static.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetJsonAttributes()
	object := attrs.GetObject()
	if object == nil {
		object, err = structpb.NewStruct(map[string]interface{}{})
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential"))
		}
	}
	cs, err := static.NewJsonCredential(
		ctx,
		storeId,
		credential.JsonObject{
			*object,
		},
		opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential"))
	}

	return cs, err
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetCredentialRequest) error {
	return handlers.ValidateGetRequest(
		handlers.NoopValidatorFn,
		req,
		credential.UsernamePasswordCredentialPrefix,
		credential.PreviousUsernamePasswordCredentialPrefix,
		credential.SshPrivateKeyCredentialPrefix,
		credential.JsonCredentialPrefix,
	)
}

func validateCreateRequest(req *pbs.CreateCredentialRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.Item.GetCredentialStoreId()), static.CredentialStorePrefix, static.PreviousCredentialStorePrefix) {
			badFields[globals.CredentialStoreIdField] = "This field must be a valid credential store id."
		}

		switch req.Item.GetType() {
		case credential.UsernamePasswordSubtype.String():
			if req.Item.GetUsernamePasswordAttributes().GetUsername().GetValue() == "" {
				badFields[usernameField] = "Field required for creating a username-password credential."
			}
			if req.Item.GetUsernamePasswordAttributes().GetPassword().GetValue() == "" {
				badFields[passwordField] = "Field required for creating a username-password credential."
			}

		case credential.SshPrivateKeySubtype.String():
			if req.Item.GetSshPrivateKeyAttributes().GetUsername().GetValue() == "" {
				badFields[usernameField] = "Field required for creating an SSH private key credential."
			}
			privateKey := req.Item.GetSshPrivateKeyAttributes().GetPrivateKey().GetValue()
			passphrase := req.Item.GetSshPrivateKeyAttributes().GetPrivateKeyPassphrase().GetValue()
			if privateKey == "" {
				badFields[privateKeyField] = "Field required for creating an SSH private key credential."
			} else {
				switch passphrase {
				case "":
					if _, err := ssh.ParsePrivateKey([]byte(privateKey)); err != nil {
						badFields[privateKeyField] = fmt.Sprintf("Unable to parse given private key value: %v.", err)
					}
				default:
					if _, err := ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase)); err != nil {
						if errors.Is(err, x509.IncorrectPasswordError) {
							badFields[privateKeyPassphraseField] = "Incorrect private key passphrase."
						} else {
							if _, err := ssh.ParsePrivateKey([]byte(privateKey)); err == nil {
								badFields[privateKeyPassphraseField] = "Passphrase supplied for unencrypted key."
							} else {
								badFields[privateKeyField] = fmt.Sprintf("Unable to parse given private key value: %v.", err)
							}
						}
					}
				}
			}

		case credential.JsonSubtype.String():
			object := req.GetItem().GetJsonAttributes().GetObject()
			if object == nil && len(object.AsMap()) <= 0 {
				badFields[objectField] = "Field required for creating a json credential."
			}
			objectBytes, err := json.Marshal(object)
			if err != nil {
				badFields[objectField] = "Unable to parse given json value"
			} else if len(objectBytes) <= 0 {
				badFields[objectField] = "Field required for creating a json credential."
			}

		default:
			badFields[globals.TypeField] = fmt.Sprintf("Unsupported credential type %q", req.Item.GetType())
		}

		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateCredentialRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case credential.UsernamePasswordSubtype:
			attrs := req.GetItem().GetUsernamePasswordAttributes()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), usernameField) && attrs.GetUsername().GetValue() == "" {
				badFields[usernameField] = "This is a required field and cannot be set to empty."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), passwordField) && attrs.GetPassword().GetValue() == "" {
				badFields[passwordField] = "This is a required field and cannot be set to empty."
			}

		case credential.SshPrivateKeySubtype:
			attrs := req.GetItem().GetSshPrivateKeyAttributes()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), usernameField) && attrs.GetUsername().GetValue() == "" {
				badFields[usernameField] = "This is a required field and cannot be set to empty."
			}
			privateKey := attrs.GetPrivateKey().GetValue()
			passphrase := attrs.GetPrivateKeyPassphrase().GetValue()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), privateKeyField) {
				if privateKey == "" {
					badFields[privateKeyField] = "This is a required field and cannot be set to empty."
				} else {
					switch passphrase {
					case "":
						if _, err := ssh.ParsePrivateKey([]byte(privateKey)); err != nil {
							badFields[privateKeyField] = fmt.Sprintf("Unable to parse given private key value: %v.", err)
						}
					default:
						if _, err := ssh.ParsePrivateKeyWithPassphrase([]byte(privateKey), []byte(passphrase)); err != nil {
							if errors.Is(err, x509.IncorrectPasswordError) {
								badFields[privateKeyPassphraseField] = "Incorrect private key passphrase."
							} else {
								if _, err := ssh.ParsePrivateKey([]byte(privateKey)); err == nil {
									badFields[privateKeyPassphraseField] = "Passphrase supplied for unencrypted key."
								} else {
									badFields[privateKeyField] = fmt.Sprintf("Unable to parse given private key value: %v.", err)
								}
							}
						}
					}
				}
			}

		case credential.JsonSubtype:
			object := req.GetItem().GetJsonAttributes().GetObject()
			if object != nil {
				objectBytes, err := json.Marshal(object.AsMap())
				if err != nil {
					badFields[objectField] = "Unable to parse given json value"
				}
				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), objectField) && len(objectBytes) <= 0 {
					badFields[objectField] = "This is a required field and cannot be set to empty."
				}
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), objectField) && object == nil {
				badFields[objectField] = "This is a required field and cannot be set to empty."
			}

		default:
			badFields[globals.IdField] = "Unknown credential type."
		}

		return badFields
	},
		credential.UsernamePasswordCredentialPrefix,
		credential.PreviousUsernamePasswordCredentialPrefix,
		credential.SshPrivateKeyCredentialPrefix,
		credential.JsonCredentialPrefix,
	)
}

func validateDeleteRequest(req *pbs.DeleteCredentialRequest) error {
	return handlers.ValidateDeleteRequest(
		handlers.NoopValidatorFn,
		req,
		credential.UsernamePasswordCredentialPrefix,
		credential.PreviousUsernamePasswordCredentialPrefix,
		credential.SshPrivateKeyCredentialPrefix,
		credential.JsonCredentialPrefix,
	)
}

func validateListRequest(req *pbs.ListCredentialsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetCredentialStoreId()), static.CredentialStorePrefix, static.PreviousCredentialStorePrefix) {
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
