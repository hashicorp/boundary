// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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
	"github.com/hashicorp/boundary/internal/listtoken"
	"github.com/hashicorp/boundary/internal/pagination"
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
	domainField               = "attributes.domain"
	privateKeyField           = "attributes.private_key"
	privateKeyPassphraseField = "attributes.private_key_passphrase"
	objectField               = "attributes.object"
	domain                    = "credential"
)

var (
	updMaskManager  handlers.MaskManager
	upMaskManager   handlers.MaskManager
	spkMaskManager  handlers.MaskManager
	jsonMaskManager handlers.MaskManager
	pMaskmanager    handlers.MaskManager

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
)

func init() {
	var err error
	if upMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.UsernamePasswordCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.UsernamePasswordAttributes{}},
	); err != nil {
		panic(err)
	}
	if spkMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.SshPrivateKeyCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.SshPrivateKeyAttributes{}},
	); err != nil {
		panic(err)
	}
	if jsonMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.JsonCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.JsonAttributes{}},
	); err != nil {
		panic(err)
	}
	if updMaskManager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.UsernamePasswordDomainCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.UsernamePasswordDomainAttributes{}},
	); err != nil {
		panic(err)
	}
	if pMaskmanager, err = handlers.NewMaskManager(
		context.Background(),
		handlers.MaskDestination{&store.PasswordCredential{}},
		handlers.MaskSource{&pb.Credential{}, &pb.PasswordAttributes{}},
	); err != nil {
		panic(err)
	}

	// TODO: refactor to remove IdActionsMap and CollectionActions package variables
	action.RegisterResource(resource.Credential, IdActions, CollectionActions)
}

// Service handles request as described by the pbs.CredentialServiceServer interface.
type Service struct {
	pbs.UnsafeCredentialServiceServer

	iamRepoFn   common.IamRepoFactory
	repoFn      common.StaticCredentialRepoFactory
	maxPageSize uint
}

var _ pbs.CredentialServiceServer = (*Service)(nil)

// NewService returns a credential service which handles credential related requests to boundary.
func NewService(
	ctx context.Context,
	iamRepo common.IamRepoFactory,
	repo common.StaticCredentialRepoFactory,
	maxPageSize uint,
) (Service, error) {
	const op = "credentials.NewService"
	if iamRepo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing iam repository")
	}
	if repo == nil {
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing static credential repository")
	}
	if maxPageSize == 0 {
		maxPageSize = uint(globals.DefaultMaxPageSize)
	}
	return Service{iamRepoFn: iamRepo, repoFn: repo, maxPageSize: maxPageSize}, nil
}

// ListCredentials implements the interface pbs.CredentialServiceServer
func (s Service) ListCredentials(ctx context.Context, req *pbs.ListCredentialsRequest) (*pbs.ListCredentialsResponse, error) {
	const op = "credentials.(Service).ListCredentials"
	if err := validateListRequest(ctx, req); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	authResults := s.authResult(ctx, req.GetCredentialStoreId(), action.List, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	pageSize := int(s.maxPageSize)
	// Use the requested page size only if it is smaller than
	// the configured max.
	if req.GetPageSize() != 0 && uint(req.GetPageSize()) < s.maxPageSize {
		pageSize = int(req.GetPageSize())
	}
	var filterItemFn func(ctx context.Context, item credential.Static) (bool, error)
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
		filterItemFn = func(ctx context.Context, item credential.Static) (bool, error) {
			outputOpts, ok := newOutputOpts(ctx, item, req.CredentialStoreId, authResults)
			if !ok {
				return ok, nil
			}
			pbItem, err := toProto(item, outputOpts...)
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
		filterItemFn = func(ctx context.Context, item credential.Static) (bool, error) {
			return true, nil
		}
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	grantsHash, err := authResults.GrantsHash(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var listResp *pagination.ListResponse[credential.Static]
	var sortBy string
	if req.GetListToken() == "" {
		sortBy = "created_time"
		listResp, err = credential.List(ctx, grantsHash, pageSize, filterItemFn, repo, req.GetCredentialStoreId())
		if err != nil {
			return nil, err
		}
	} else {
		listToken, err := handlers.ParseListToken(ctx, req.GetListToken(), resource.Credential, grantsHash)
		if err != nil {
			return nil, err
		}
		switch st := listToken.Subtype.(type) {
		case *listtoken.PaginationToken:
			sortBy = "created_time"
			listResp, err = credential.ListPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetCredentialStoreId())
			if err != nil {
				return nil, err
			}
		case *listtoken.StartRefreshToken:
			sortBy = "updated_time"
			listResp, err = credential.ListRefresh(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetCredentialStoreId())
			if err != nil {
				return nil, err
			}
		case *listtoken.RefreshToken:
			sortBy = "updated_time"
			listResp, err = credential.ListRefreshPage(ctx, grantsHash, pageSize, filterItemFn, listToken, repo, req.GetCredentialStoreId())
			if err != nil {
				return nil, err
			}
		default:
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "unexpected list token subtype: %T", st)
		}
	}

	finalItems := make([]*pb.Credential, 0, len(listResp.Items))
	for _, item := range listResp.Items {
		outputOpts, ok := newOutputOpts(ctx, item, req.CredentialStoreId, authResults)
		if !ok {
			continue
		}
		pbItem, err := toProto(item, outputOpts...)
		if err != nil {
			return nil, err
		}
		finalItems = append(finalItems, pbItem)
	}
	respType := "delta"
	if listResp.CompleteListing {
		respType = "complete"
	}
	resp := &pbs.ListCredentialsResponse{
		Items:        finalItems,
		EstItemCount: uint32(listResp.EstimatedItemCount),
		RemovedIds:   listResp.DeletedIds,
		ResponseType: respType,
		SortBy:       sortBy,
		SortDir:      "desc",
	}

	if listResp.ListToken != nil {
		resp.ListToken, err = handlers.MarshalListToken(ctx, listResp.ListToken, pbs.ResourceType_RESOURCE_TYPE_CREDENTIAL)
		if err != nil {
			return nil, err
		}
	}

	return resp, nil
}

// GetCredential implements the interface pbs.CredentialServiceServer.
func (s Service) GetCredential(ctx context.Context, req *pbs.GetCredentialRequest) (*pbs.GetCredentialResponse, error) {
	const op = "credentials.(Service).GetCredential"

	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
	authResults := s.authResult(ctx, req.GetItem().GetCredentialStoreId(), action.Create, false)
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
	authResults := s.authResult(ctx, req.GetId(), action.Update, false)
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
	outputOpts = append(outputOpts, handlers.WithOutputFields(outputFields))
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
	authResults := s.authResult(ctx, req.GetId(), action.Delete, false)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, authResults.Scope.GetId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
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
	case credential.UsernamePasswordDomainSubtype.String():
		cred, err := toUsernamePasswordDomainStorageCredential(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, err := repo.CreateUsernamePasswordDomainCredential(ctx, scopeId, cred)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create credential"))
		}
		if out == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create credential but no error returned from repository.")
		}
		return out, nil
	case credential.PasswordSubtype.String():
		cred, err := toPasswordStorageCredential(ctx, item.GetCredentialStoreId(), item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, err := repo.CreatePasswordCredential(ctx, scopeId, cred)
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

	switch globals.ResourceInfoFromPrefix(id).Subtype {
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
	case credential.UsernamePasswordDomainSubtype:
		dbMasks = append(dbMasks, updMaskManager.Translate(masks)...)
		if len(dbMasks) == 0 {
			return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
		}

		cred, err := toUsernamePasswordDomainStorageCredential(ctx, storeId, in)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert to username/password/domain storage credential"))
		}
		cred.PublicId = id
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, rowsUpdated, err := repo.UpdateUsernamePasswordDomainCredential(ctx, scopeId, cred, item.GetVersion(), dbMasks)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential"))
		}
		if rowsUpdated == 0 {
			return nil, handlers.NotFoundErrorf("Credential %q doesn't exist or incorrect version provided.", id)
		}
		return out, nil
	case credential.PasswordSubtype:
		dbMasks = append(dbMasks, pMaskmanager.Translate(masks)...)
		if len(dbMasks) == 0 {
			return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
		}

		cred, err := toPasswordStorageCredential(ctx, storeId, in)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to convert to password storage credential"))
		}
		cred.PublicId = id
		repo, err := s.repoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		out, rowsUpdated, err := repo.UpdatePasswordCredential(ctx, scopeId, cred, item.GetVersion(), dbMasks)
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

func (s Service) authResult(ctx context.Context, id string, a action.Type, isRecursive bool) auth.VerifyResults {
	const op = "credentials.(Service).authResult"
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
	if err != nil {
		res.Error = err
		return res
	}

	var parentId string
	opts := []auth.Option{auth.WithAction(a), auth.WithRecursive(isRecursive)}
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
	return auth.Verify(ctx, resource.Credential, opts...)
}

func newOutputOpts(
	ctx context.Context,
	item credential.Static,
	credentialStoreId string,
	authResults auth.VerifyResults,
) ([]handlers.Option, bool) {
	res := perms.Resource{
		ScopeId:       authResults.Scope.Id,
		ParentScopeId: authResults.Scope.ParentScopeId,
		Type:          resource.Credential,
		Pin:           credentialStoreId,
	}
	res.Id = item.GetPublicId()
	authorizedActions := authResults.FetchActionSetForId(ctx, item.GetPublicId(), IdActions, auth.WithResource(&res)).Strings()
	if len(authorizedActions) == 0 {
		return nil, false
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
	return outputOpts, true
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
		case *static.UsernamePasswordDomainCredential:
			out.Type = credential.UsernamePasswordDomainSubtype.String()
		case *static.PasswordCredential:
			out.Type = credential.PasswordSubtype.String()
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
	case *static.UsernamePasswordDomainCredential:
		if outputFields.Has(globals.AttributesField) {
			out.Attrs = &pb.Credential_UsernamePasswordDomainAttributes{
				UsernamePasswordDomainAttributes: &pb.UsernamePasswordDomainAttributes{
					Username:     wrapperspb.String(cred.GetUsername()),
					PasswordHmac: base64.RawURLEncoding.EncodeToString(cred.GetPasswordHmac()),
					Domain:       wrapperspb.String(cred.GetDomain()),
				},
			}
		}
	case *static.PasswordCredential:
		if outputFields.Has(globals.AttributesField) {
			out.Attrs = &pb.Credential_PasswordAttributes{
				PasswordAttributes: &pb.PasswordAttributes{
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

func toUsernamePasswordDomainStorageCredential(ctx context.Context, storeId string, in *pb.Credential) (out *static.UsernamePasswordDomainCredential, err error) {
	const op = "credentials.toUsernamePasswordDomainStorageCredential"
	var opts []static.Option
	if in.GetName() != nil {
		opts = append(opts, static.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, static.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetUsernamePasswordDomainAttributes()
	cs, err := static.NewUsernamePasswordDomainCredential(
		storeId,
		attrs.GetUsername().GetValue(),
		credential.Password(attrs.GetPassword().GetValue()),
		attrs.GetDomain().GetValue(),
		opts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential"))
	}

	return cs, err
}

func toPasswordStorageCredential(ctx context.Context, storeId string, in *pb.Credential) (out *static.PasswordCredential, err error) {
	const op = "credentials.toPasswordStorageCredential"
	var opts []static.Option
	if in.GetName() != nil {
		opts = append(opts, static.WithName(in.GetName().GetValue()))
	}
	if in.GetDescription() != nil {
		opts = append(opts, static.WithDescription(in.GetDescription().GetValue()))
	}

	attrs := in.GetPasswordAttributes()
	cs, err := static.NewPasswordCredential(
		storeId,
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
		object, err = structpb.NewStruct(map[string]any{})
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to build credential"))
		}
	}
	cs, err := static.NewJsonCredential(
		ctx,
		storeId,
		credential.JsonObject{
			Struct: object,
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
		globals.UsernamePasswordCredentialPrefix,
		globals.UsernamePasswordCredentialPreviousPrefix,
		globals.UsernamePasswordDomainCredentialPrefix,
		globals.PasswordCredentialPrefix,
		globals.SshPrivateKeyCredentialPrefix,
		globals.JsonCredentialPrefix,
	)
}

func validateCreateRequest(req *pbs.CreateCredentialRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.Item.GetCredentialStoreId()), globals.StaticCredentialStorePrefix, globals.StaticCredentialStorePreviousPrefix) {
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
		case credential.UsernamePasswordDomainSubtype.String():
			if req.Item.GetUsernamePasswordDomainAttributes().GetUsername().GetValue() == "" {
				badFields[usernameField] = "Field required for creating a username-password-domain credential."
			}
			if req.Item.GetUsernamePasswordDomainAttributes().GetPassword().GetValue() == "" {
				badFields[passwordField] = "Field required for creating a username-password-domain credential."
			}
			if req.Item.GetUsernamePasswordDomainAttributes().GetDomain().GetValue() == "" {
				badFields[domainField] = "Field required for creating a username-password-domain credential."
			}
		case credential.PasswordSubtype.String():
			if req.Item.GetPasswordAttributes().GetPassword().GetValue() == "" {
				badFields[passwordField] = "Field required for creating a password credential."
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
			if object == nil || len(object.AsMap()) <= 0 {
				badFields[objectField] = "This is a required field and cannot be set to empty."
			} else if _, err := json.Marshal(object); err != nil {
				badFields[objectField] = "Unable to parse given json value"
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
		switch globals.ResourceInfoFromPrefix(req.GetId()).Subtype {
		case credential.UsernamePasswordSubtype:
			attrs := req.GetItem().GetUsernamePasswordAttributes()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), usernameField) && attrs.GetUsername().GetValue() == "" {
				badFields[usernameField] = "This is a required field and cannot be set to empty."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), passwordField) && attrs.GetPassword().GetValue() == "" {
				badFields[passwordField] = "This is a required field and cannot be set to empty."
			}

		case credential.UsernamePasswordDomainSubtype:
			attrs := req.GetItem().GetUsernamePasswordDomainAttributes()
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), usernameField) && attrs.GetUsername().GetValue() == "" {
				badFields[usernameField] = "This is a required field and cannot be set to empty."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), passwordField) && attrs.GetPassword().GetValue() == "" {
				badFields[passwordField] = "This is a required field and cannot be set to empty."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), domainField) && attrs.GetDomain().GetValue() == "" {
				badFields[domainField] = "This is a required field and cannot be set to empty."
			}
		case credential.PasswordSubtype:
			attrs := req.GetItem().GetPasswordAttributes()
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
			if handlers.MaskContainsPrefix(req.GetUpdateMask().GetPaths(), objectField) {
				object := req.GetItem().GetJsonAttributes().GetObject()
				if object == nil || len(object.AsMap()) <= 0 {
					badFields[objectField] = "This is a required field and cannot be set to empty"
				} else if _, err := json.Marshal(object); err != nil {
					badFields[objectField] = "Unable to parse given json value"
				}
			}
		default:
			badFields[globals.IdField] = "Unknown credential type."
		}

		return badFields
	},
		globals.UsernamePasswordCredentialPrefix,
		globals.UsernamePasswordCredentialPreviousPrefix,
		globals.UsernamePasswordDomainCredentialPrefix,
		globals.PasswordCredentialPrefix,
		globals.SshPrivateKeyCredentialPrefix,
		globals.JsonCredentialPrefix,
	)
}

func validateDeleteRequest(req *pbs.DeleteCredentialRequest) error {
	return handlers.ValidateDeleteRequest(
		handlers.NoopValidatorFn,
		req,
		globals.UsernamePasswordCredentialPrefix,
		globals.UsernamePasswordCredentialPreviousPrefix,
		globals.UsernamePasswordDomainCredentialPrefix,
		globals.PasswordCredentialPrefix,
		globals.SshPrivateKeyCredentialPrefix,
		globals.JsonCredentialPrefix,
	)
}

func validateListRequest(ctx context.Context, req *pbs.ListCredentialsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetCredentialStoreId()), globals.StaticCredentialStorePrefix, globals.StaticCredentialStorePreviousPrefix) {
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
