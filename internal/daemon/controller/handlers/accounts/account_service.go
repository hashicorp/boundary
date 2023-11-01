// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package accounts

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/auth/password"
	pwstore "github.com/hashicorp/boundary/internal/auth/password/store"
	requestauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/common"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/errors"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/requests"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/subtypes"
	pb "github.com/hashicorp/boundary/sdk/pbs/controller/api/resources/accounts"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// general auth method field names
	versionField      = "version"
	authMethodIdField = "auth_method_id"
	typeField         = "type"
	attributesField   = "attributes"
	filterField       = "filter"
	idField           = "id"

	// password field names
	loginNameKey         = "login_name"
	newPasswordField     = "new_password"
	currentPasswordField = "current_password"

	// oidc field names
	issuerField     = "attributes.issuer"
	subjectField    = "attributes.subject"
	nameClaimField  = "attributes.full_name"
	emailClaimField = "attributes.email"

	// ldap field names
	loginAttrField    = "attributes.login_name"
	nameAttrField     = "attributes.full_name"
	emailAttrField    = "attributes.email"
	dnAttrField       = "attributes.dn"
	memberOfAttrField = "attributes.member_of_groups"

	domain = "auth"
)

var (
	pwMaskManager   handlers.MaskManager
	oidcMaskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = map[globals.Subtype]action.ActionSet{
		globals.PasswordSubtype: {
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
			action.SetPassword,
			action.ChangePassword,
		},
		globals.OidcSubtype: {
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		},
		globals.LdapSubtype: {
			action.NoOp,
			action.Read,
			action.Update,
			action.Delete,
		},
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
	if pwMaskManager, err = handlers.NewMaskManager(context.Background(), handlers.MaskDestination{&pwstore.Account{}}, handlers.MaskSource{&pb.Account{}, &pb.PasswordAccountAttributes{}}); err != nil {
		panic(err)
	}
	if oidcMaskManager, err = handlers.NewMaskManager(context.Background(), handlers.MaskDestination{&oidcstore.Account{}}, handlers.MaskSource{&pb.Account{}, &pb.OidcAccountAttributes{}}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.AccountServiceServer interface.
type Service struct {
	pbs.UnsafeAccountServiceServer

	pwRepoFn   common.PasswordAuthRepoFactory
	oidcRepoFn common.OidcAuthRepoFactory
	ldapRepoFn common.LdapAuthRepoFactory
}

var _ pbs.AccountServiceServer = (*Service)(nil)

// NewService returns a account service which handles account related requests to boundary.
func NewService(ctx context.Context, pwRepo common.PasswordAuthRepoFactory, oidcRepo common.OidcAuthRepoFactory, ldapRepo common.LdapAuthRepoFactory) (Service, error) {
	const op = "accounts.NewService"
	switch {
	case pwRepo == nil:
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing password repository")
	case oidcRepo == nil:
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing oidc repository")
	case ldapRepo == nil:
		return Service{}, errors.New(ctx, errors.InvalidParameter, op, "missing ldap repository")
	}
	return Service{pwRepoFn: pwRepo, oidcRepoFn: oidcRepo, ldapRepoFn: ldapRepo}, nil
}

// ListAccounts implements the interface pbs.AccountServiceServer.
func (s Service) ListAccounts(ctx context.Context, req *pbs.ListAccountsRequest) (*pbs.ListAccountsResponse, error) {
	if err := validateListRequest(ctx, req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetAuthMethodId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ul, err := s.listFromRepo(ctx, req.GetAuthMethodId())
	if err != nil {
		return nil, err
	}
	if len(ul) == 0 {
		return &pbs.ListAccountsResponse{}, nil
	}

	filter, err := handlers.NewFilter(ctx, req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Account, 0, len(ul))

	res := perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.Account,
		Pin:     req.GetAuthMethodId(),
	}
	for _, acct := range ul {
		res.Id = acct.GetPublicId()
		authorizedActions := authResults.FetchActionSetForId(ctx, acct.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, acct.GetPublicId())], requestauth.WithResource(&res)).Strings()
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

		item, err := toProto(ctx, acct, outputOpts...)
		if err != nil {
			return nil, err
		}

		// This comes last so that we can use item fields in the filter after
		// the allowed fields are populated above
		filterable, err := subtypes.Filterable(item)
		if err != nil {
			return nil, err
		}
		if filter.Match(filterable) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListAccountsResponse{Items: finalItems}, nil
}

// GetAccount implements the interface pbs.AccountServiceServer.
func (s Service) GetAccount(ctx context.Context, req *pbs.GetAccountRequest) (*pbs.GetAccountResponse, error) {
	const op = "accounts.(Service).GetAccount"

	if err := validateGetRequest(ctx, req); err != nil {
		return nil, err
	}

	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	acct, mgIds, err := s.getFromRepo(ctx, req.GetId())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, acct.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, acct.GetPublicId())]).Strings()))
	}
	if outputFields.Has(globals.ManagedGroupIdsField) {
		outputOpts = append(outputOpts, handlers.WithManagedGroupIds(mgIds))
	}

	item, err := toProto(ctx, acct, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.GetAccountResponse{Item: item}, nil
}

// CreateAccount implements the interface pbs.AccountServiceServer.
func (s Service) CreateAccount(ctx context.Context, req *pbs.CreateAccountRequest) (*pbs.CreateAccountResponse, error) {
	const op = "accounts.(Service).CreateAccount"

	if err := validateCreateRequest(ctx, req); err != nil {
		return nil, err
	}

	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetAuthMethodId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	acct, err := s.createInRepo(ctx, authMeth, req.GetItem())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, acct.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, acct.GetPublicId())]).Strings()))
	}

	item, err := toProto(ctx, acct, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.CreateAccountResponse{Item: item, Uri: fmt.Sprintf("accounts/%s", item.GetId())}, nil
}

// UpdateAccount implements the interface pbs.AccountServiceServer.
func (s Service) UpdateAccount(ctx context.Context, req *pbs.UpdateAccountRequest) (*pbs.UpdateAccountResponse, error) {
	const op = "accounts.(Service).UpdateAccount"

	if err := validateUpdateRequest(ctx, req); err != nil {
		return nil, err
	}

	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	acct, err := s.updateInRepo(ctx, authResults.Scope.GetId(), authMeth.GetPublicId(), req)
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, acct.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, acct.GetPublicId())]).Strings()))
	}

	item, err := toProto(ctx, acct, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.UpdateAccountResponse{Item: item}, nil
}

// DeleteAccount implements the interface pbs.AccountServiceServer.
func (s Service) DeleteAccount(ctx context.Context, req *pbs.DeleteAccountRequest) (*pbs.DeleteAccountResponse, error) {
	if err := validateDeleteRequest(ctx, req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, authResults.Scope.GetId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// ChangePassword implements the interface pbs.AccountServiceServer.
func (s Service) ChangePassword(ctx context.Context, req *pbs.ChangePasswordRequest) (*pbs.ChangePasswordResponse, error) {
	const op = "accounts.(Service).ChangePassword"

	if err := validateChangePasswordRequest(ctx, req); err != nil {
		return nil, err
	}

	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.ChangePassword)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	acct, err := s.changePasswordInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetVersion(), req.GetCurrentPassword(), req.GetNewPassword())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, acct.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, acct.GetPublicId())]).Strings()))
	}

	item, err := toProto(ctx, acct, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.ChangePasswordResponse{Item: item}, nil
}

// SetPassword implements the interface pbs.AccountServiceServer.
func (s Service) SetPassword(ctx context.Context, req *pbs.SetPasswordRequest) (*pbs.SetPasswordResponse, error) {
	const op = "accounts.(Service).SetPassword"

	if err := validateSetPasswordRequest(ctx, req); err != nil {
		return nil, err
	}

	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.SetPassword)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	acct, err := s.setPasswordInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetVersion(), req.GetPassword())
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
		outputOpts = append(outputOpts, handlers.WithAuthorizedActions(authResults.FetchActionSetForId(ctx, acct.GetPublicId(), IdActions[subtypes.SubtypeFromId(domain, acct.GetPublicId())]).Strings()))
	}

	item, err := toProto(ctx, acct, outputOpts...)
	if err != nil {
		return nil, err
	}

	return &pbs.SetPasswordResponse{Item: item}, nil
}

// getFromRepo returns the account and, if available, managed groups the account
// belongs to within the auth method
func (s Service) getFromRepo(ctx context.Context, id string) (auth.Account, []string, error) {
	var acct auth.Account
	var mgIds []string
	switch subtypes.SubtypeFromId(domain, id) {
	case globals.PasswordSubtype:
		repo, err := s.pwRepoFn()
		if err != nil {
			return nil, nil, err
		}
		a, err := repo.LookupAccount(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil, handlers.NotFoundErrorf("Account %q doesn't exist.", id)
			}
			return nil, nil, err
		}
		acct = a
	case globals.OidcSubtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, nil, err
		}
		a, err := repo.LookupAccount(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil, handlers.NotFoundErrorf("Account %q doesn't exist.", id)
			}
			return nil, nil, err
		}
		mgs, err := repo.ListManagedGroupMembershipsByMember(ctx, a.GetPublicId())
		if err != nil {
			return nil, nil, err
		}
		for _, mg := range mgs {
			mgIds = append(mgIds, mg.GetManagedGroupId())
		}
		acct = a
	case globals.LdapSubtype:
		repo, err := s.ldapRepoFn()
		if err != nil {
			return nil, nil, err
		}
		a, err := repo.LookupAccount(ctx, id)
		if err != nil {
			return nil, nil, err
		}
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, nil, handlers.NotFoundErrorf("LDAP account %q doesn't exist.", id)
			}
			return nil, nil, err
		}
		mgs, err := repo.ListManagedGroupMembershipsByMember(ctx, a.GetPublicId())
		if err != nil {
			return nil, nil, err
		}
		for _, mg := range mgs {
			mgIds = append(mgIds, mg.GetManagedGroupId())
		}
		acct = a
	default:
		return nil, nil, handlers.NotFoundErrorf("Unrecognized id.")
	}
	return acct, mgIds, nil
}

func (s Service) createPwInRepo(ctx context.Context, am auth.AuthMethod, item *pb.Account) (*password.Account, error) {
	const op = "accounts.(Service).createPwInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	pwAttrs := item.GetPasswordAccountAttributes()
	opts := []password.Option{password.WithLoginName(pwAttrs.GetLoginName())}
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	a, err := password.NewAccount(ctx, am.GetPublicId(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build account for creation: %v.", err)
	}
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}

	var createOpts []password.Option
	if pwAttrs.GetPassword() != nil {
		createOpts = append(createOpts, password.WithPassword(pwAttrs.GetPassword().GetValue()))
	}
	out, err := repo.CreateAccount(ctx, am.GetScopeId(), a, createOpts...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create account but no error returned from repository.")
	}
	return out, nil
}

func (s Service) createOidcInRepo(ctx context.Context, am auth.AuthMethod, item *pb.Account) (*oidc.Account, error) {
	const op = "accounts.(Service).createOidcInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var opts []oidc.Option
	if item.GetName() != nil {
		opts = append(opts, oidc.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, oidc.WithDescription(item.GetDescription().GetValue()))
	}
	attrs := item.GetOidcAccountAttributes()
	if attrs.GetIssuer() != "" {
		u, err := url.Parse(attrs.GetIssuer())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to parse issuer"), errors.WithCode(errors.InvalidParameter))
		}
		opts = append(opts, oidc.WithIssuer(u))
	}
	a, err := oidc.NewAccount(ctx, am.GetPublicId(), attrs.GetSubject(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build account for creation: %v.", err)
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}

	out, err := repo.CreateAccount(ctx, am.GetScopeId(), a)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create account"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create account but no error returned from repository.")
	}
	return out, nil
}

func (s Service) createLdapInRepo(ctx context.Context, am auth.AuthMethod, item *pb.Account) (*ldap.Account, error) {
	const op = "accounts.(Service).createLdapInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var opts []ldap.Option
	if item.GetName() != nil {
		opts = append(opts, ldap.WithName(ctx, item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, ldap.WithDescription(ctx, item.GetDescription().GetValue()))
	}
	a, err := ldap.NewAccount(ctx, am.GetScopeId(), am.GetPublicId(), item.GetLdapAccountAttributes().GetLoginName(), opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build account for creation: %v.", err)
	}
	repo, err := s.ldapRepoFn()
	if err != nil {
		return nil, err
	}

	out, err := repo.CreateAccount(ctx, a)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create account"))
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create account but no error returned from repository.")
	}
	return out, nil
}

func (s Service) createInRepo(ctx context.Context, am auth.AuthMethod, item *pb.Account) (auth.Account, error) {
	const op = "accounts.(Service).createInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "missing item")
	}
	var out auth.Account
	switch subtypes.SubtypeFromId(domain, am.GetPublicId()) {
	case globals.PasswordSubtype:
		am, err := s.createPwInRepo(ctx, am, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create account but no error returned from repository.")
		}
		out = am
	case globals.OidcSubtype:
		am, err := s.createOidcInRepo(ctx, am, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create account but no error returned from repository.")
		}
		out = am
	case globals.LdapSubtype:
		am, err := s.createLdapInRepo(ctx, am, item)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if am == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create ldap account but no error returned from repository.")
		}
		out = am
	}

	return out, nil
}

func (s Service) updatePwInRepo(ctx context.Context, scopeId, authMethId, id string, mask []string, item *pb.Account) (*password.Account, error) {
	const op = "accounts.(Service).updatePwInRepo"
	u, err := toStoragePwAccount(ctx, authMethId, item)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build account for update: %v.", err)
	}
	u.PublicId = id

	version := item.GetVersion()

	dbMask := pwMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateAccount(ctx, scopeId, u, version, dbMask)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.PasswordTooShort), err):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"attributes.login_name": "Length too short."})
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Account %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updateOidcInRepo(ctx context.Context, scopeId, amId, id string, mask []string, item *pb.Account) (*oidc.Account, error) {
	const op = "accounts.(Service).updateOidcInRepo"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil account.")
	}
	u := oidc.AllocAccount()
	u.PublicId = id
	if item.GetName() != nil {
		u.Name = item.GetName().GetValue()
	}
	if item.GetDescription() != nil {
		u.Description = item.GetDescription().GetValue()
	}

	version := item.GetVersion()

	dbMask := oidcMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateAccount(ctx, scopeId, u, version, dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update account"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Account %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updateLdapInRepo(ctx context.Context, scopeId, amId, id string, mask []string, item *pb.Account) (*ldap.Account, error) {
	const op = "accounts.(Service).updateLdapInRepo"
	switch {
	case item == nil:
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "nil account.")
	case scopeId == "":
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "missing scope id")
	case amId == "":
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "missing auth method id")
	case id == "":
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "missing id")
	case len(mask) == 0:
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "missing mask.")
	}
	u := ldap.AllocAccount()
	u.PublicId = id
	u.ScopeId = scopeId
	u.AuthMethodId = amId
	if item.GetName() != nil {
		u.Name = item.GetName().GetValue()
	}
	if item.GetDescription() != nil {
		u.Description = item.GetDescription().GetValue()
	}

	// we don't need a mask mgr, since none of the attributes fields are
	// updatable.  Just a simple split on commas looking for multiple paths in
	// one mask string
	dbMask := []string{}
	for _, v := range mask {
		vSplit := strings.Split(v, ",")
		for _, m := range vSplit {
			switch m {
			case globals.NameField, globals.DescriptionField:
				dbMask = append(dbMask, vSplit...)
			case globals.VersionField:
				// no-op
			default:
				return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
			}
		}
	}

	repo, err := s.ldapRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, rowsUpdated, err := repo.UpdateAccount(ctx, scopeId, u, item.GetVersion(), dbMask)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to update account"))
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Account %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, authMethodId string, req *pbs.UpdateAccountRequest) (auth.Account, error) {
	const op = "accounts.(Service).updateInRepo"
	var out auth.Account
	switch subtypes.SubtypeFromId(domain, req.GetId()) {
	case globals.PasswordSubtype:
		a, err := s.updatePwInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if a == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update account but no error returned from repository.")
		}
		out = a
	case globals.OidcSubtype:
		a, err := s.updateOidcInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if a == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update account but no error returned from repository.")
		}
		out = a
	case globals.LdapSubtype:
		a, err := s.updateLdapInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		if a == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update account but no error returned from repository.")
		}
		out = a
	}
	return out, nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	const op = "accounts.(Service).deleteFromRepo"
	var rows int
	var err error
	switch subtypes.SubtypeFromId(domain, id) {
	case globals.PasswordSubtype:
		repo, iErr := s.pwRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteAccount(ctx, scopeId, id)
	case globals.OidcSubtype:
		repo, iErr := s.oidcRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteAccount(ctx, scopeId, id)
	case globals.LdapSubtype:
		repo, iErr := s.ldapRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteAccount(ctx, id)
	}
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, errors.Wrap(ctx, err, op)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, authMethodId string) ([]auth.Account, error) {
	const op = "accounts.(Service).listFromRepo"

	var outUl []auth.Account
	switch subtypes.SubtypeFromId(domain, authMethodId) {
	case globals.PasswordSubtype:
		pwRepo, err := s.pwRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		pwl, err := pwRepo.ListAccounts(ctx, authMethodId, password.WithLimit(-1))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, a := range pwl {
			outUl = append(outUl, a)
		}
	case globals.OidcSubtype:
		oidcRepo, err := s.oidcRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		oidcl, err := oidcRepo.ListAccounts(ctx, authMethodId, oidc.WithLimit(-1))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, a := range oidcl {
			outUl = append(outUl, a)
		}
	case globals.LdapSubtype:
		ldapRepo, err := s.ldapRepoFn()
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		ldapList, err := ldapRepo.ListAccounts(ctx, authMethodId, ldap.WithLimit(ctx, -1))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		for _, a := range ldapList {
			outUl = append(outUl, a)
		}
	}
	return outUl, nil
}

func (s Service) changePasswordInRepo(ctx context.Context, scopeId, id string, version uint32, currentPassword, newPassword string) (auth.Account, error) {
	const op = "account.(Service).changePasswordInRepo"
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, err := repo.ChangePassword(ctx, scopeId, id, currentPassword, newPassword, version)
	if err != nil {
		switch {
		case errors.IsNotFoundError(err):
			return nil, handlers.NotFoundErrorf("Account not found.")
		case errors.Match(errors.T(errors.PasswordTooShort), err):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"new_password": "Password is too short."})
		case errors.Match(errors.T(errors.PasswordsEqual), err):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"new_password": "New password equal to current password."})
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "Failed to change password.")
	}
	return out, nil
}

func (s Service) setPasswordInRepo(ctx context.Context, scopeId, id string, version uint32, pw string) (auth.Account, error) {
	const op = "accounts.(Service).setPasswordInRepo"

	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	out, err := repo.SetPassword(ctx, scopeId, id, pw, version)
	if err != nil {
		switch {
		case errors.IsNotFoundError(err):
			return nil, handlers.NotFoundErrorf("Account not found.")
		case errors.Match(errors.T(errors.PasswordTooShort), err):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"password": "Password is too short."})
		}
		return nil, errors.Wrap(ctx, err, op)
	}
	return out, nil
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (auth.AuthMethod, requestauth.VerifyResults) {
	res := requestauth.VerifyResults{}
	pwRepo, err := s.pwRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}
	oidcRepo, err := s.oidcRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}
	ldapRepo, err := s.ldapRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var parentId string
	opts := []requestauth.Option{requestauth.WithType(resource.Account), requestauth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		switch subtypes.SubtypeFromId(domain, id) {
		case globals.PasswordSubtype:
			acct, err := pwRepo.LookupAccount(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if acct == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = acct.GetAuthMethodId()
		case globals.OidcSubtype:
			acct, err := oidcRepo.LookupAccount(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if acct == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = acct.GetAuthMethodId()
		case globals.LdapSubtype:
			acct, err := ldapRepo.LookupAccount(ctx, id)
			if err != nil {
				res.Error = err
				return nil, res
			}
			if acct == nil {
				res.Error = handlers.NotFoundError()
				return nil, res
			}
			parentId = acct.GetAuthMethodId()
		}
		opts = append(opts, requestauth.WithId(id))
	}

	var authMeth auth.AuthMethod
	switch subtypes.SubtypeFromId(domain, parentId) {
	case globals.PasswordSubtype:
		am, err := pwRepo.LookupAuthMethod(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if am == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		authMeth = am
	case globals.OidcSubtype:
		am, err := oidcRepo.LookupAuthMethod(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if am == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		authMeth = am
	case globals.LdapSubtype:
		am, err := ldapRepo.LookupAuthMethod(ctx, parentId)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if am == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		authMeth = am
	}
	opts = append(opts, requestauth.WithScopeId(authMeth.GetScopeId()), requestauth.WithPin(parentId))
	return authMeth, requestauth.Verify(ctx, opts...)
}

func toProto(ctx context.Context, in auth.Account, opt ...handlers.Option) (*pb.Account, error) {
	const op = "accounts.(Service).toProto"

	opts := handlers.GetOpts(opt...)
	if opts.WithOutputFields == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "output fields not found when building account proto")
	}
	outputFields := *opts.WithOutputFields

	out := pb.Account{}
	if outputFields.Has(globals.IdField) {
		out.Id = in.GetPublicId()
	}
	if outputFields.Has(globals.AuthMethodIdField) {
		out.AuthMethodId = in.GetAuthMethodId()
	}
	if outputFields.Has(globals.DescriptionField) && in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if outputFields.Has(globals.NameField) && in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
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
	if outputFields.Has(globals.ManagedGroupIdsField) {
		out.ManagedGroupIds = opts.WithManagedGroupIds
	}
	switch i := in.(type) {
	case *password.Account:
		if outputFields.Has(globals.TypeField) {
			out.Type = globals.PasswordSubtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}
		out.Attrs = &pb.Account_PasswordAccountAttributes{
			PasswordAccountAttributes: &pb.PasswordAccountAttributes{
				LoginName: i.GetLoginName(),
			},
		}
	case *oidc.Account:
		if outputFields.Has(globals.TypeField) {
			out.Type = globals.OidcSubtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}
		attrs := &pb.Account_OidcAccountAttributes{
			OidcAccountAttributes: &pb.OidcAccountAttributes{
				Issuer:   i.GetIssuer(),
				Subject:  i.GetSubject(),
				FullName: i.GetFullName(),
				Email:    i.GetEmail(),
			},
		}
		if s := i.GetTokenClaims(); s != "" {
			m := make(map[string]any)
			var err error
			if err = json.Unmarshal([]byte(s), &m); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error unmarshaling stored token claims"))
			}
			if attrs.OidcAccountAttributes.TokenClaims, err = structpb.NewStruct(m); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error converting stored token claims to protobuf struct"))
			}
		}
		if s := i.GetUserinfoClaims(); s != "" {
			m := make(map[string]any)
			var err error
			if err = json.Unmarshal([]byte(s), &m); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error unmarshaling stored userinfo claims"))
			}
			if attrs.OidcAccountAttributes.UserinfoClaims, err = structpb.NewStruct(m); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg("error converting stored userinfo claims to protobuf struct"))
			}
		}
		out.Attrs = attrs
	case *ldap.Account:
		if outputFields.Has(globals.TypeField) {
			out.Type = globals.LdapSubtype.String()
		}
		if !outputFields.Has(globals.AttributesField) {
			break
		}
		attrs := &pb.Account_LdapAccountAttributes{
			LdapAccountAttributes: &pb.LdapAccountAttributes{
				LoginName: i.GetLoginName(),
				FullName:  i.GetFullName(),
				Email:     i.GetEmail(),
				Dn:        i.GetDn(),
			},
		}
		if encodedGroups := i.GetMemberOfGroups(); encodedGroups != "" {
			var decodedGroups []string
			if err := json.Unmarshal([]byte(encodedGroups), &decodedGroups); err != nil {
				return nil, errors.Wrap(ctx, err, op, errors.WithMsg(""))
			}
			attrs.LdapAccountAttributes.MemberOfGroups = decodedGroups
		}
		out.Attrs = attrs
	}
	return &out, nil
}

func toStoragePwAccount(ctx context.Context, amId string, item *pb.Account) (*password.Account, error) {
	const op = "accounts.toStoragePwAccount"
	if item == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil account.")
	}
	var opts []password.Option
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := password.NewAccount(ctx, amId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build account for creation: %v.", err)
	}

	attrs := item.GetPasswordAccountAttributes()
	if attrs.GetLoginName() != "" {
		u.LoginName = attrs.GetLoginName()
	}
	return u, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//   - The path passed in is correctly formatted
//   - All required parameters are set
//   - There are no conflicting parameters provided
func validateGetRequest(ctx context.Context, req *pbs.GetAccountRequest) error {
	const op = "accounts.validateGetRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, globals.PasswordAccountPreviousPrefix, globals.PasswordAccountPrefix, globals.OidcAccountPrefix, globals.LdapAccountPrefix)
}

func validateCreateRequest(ctx context.Context, req *pbs.CreateAccountRequest) error {
	const op = "accounts.validateCreateRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetAuthMethodId() == "" {
			badFields[authMethodIdField] = "This field is required."
		}
		switch subtypes.SubtypeFromId(domain, req.GetItem().GetAuthMethodId()) {
		case globals.PasswordSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != globals.PasswordSubtype.String() {
				badFields[typeField] = "Doesn't match the parent resource's type."
			}
			attrs := req.GetItem().GetPasswordAccountAttributes()
			switch {
			case attrs == nil:
				badFields["attributes"] = "This is a required field."
			default:
				if attrs.GetLoginName() == "" {
					badFields[loginNameKey] = "This is a required field for this type."
				}
			}
		case globals.OidcSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != globals.OidcSubtype.String() {
				badFields[typeField] = "Doesn't match the parent resource's type."
			}
			attrs := req.GetItem().GetOidcAccountAttributes()
			switch {
			case attrs == nil:
				badFields["attributes"] = "This is a required field."
			default:
				if attrs.GetSubject() == "" {
					badFields[subjectField] = "This is a required field for this type."
				}
				if attrs.GetIssuer() != "" {
					du, err := url.Parse(attrs.GetIssuer())
					if err != nil {
						badFields[issuerField] = fmt.Sprintf("Cannot be parsed as a url. %v", err)
					}
					if trimmed := strings.TrimSuffix(strings.TrimSuffix(du.RawPath, "/"), "/.well-known/openid-configuration"); trimmed != "" {
						badFields[issuerField] = "The path segment of the url should be empty."
					}
				}
				if attrs.GetFullName() != "" {
					badFields[nameClaimField] = "This is a read only field."
				}
				if attrs.GetEmail() != "" {
					badFields[emailClaimField] = "This is a read only field."
				}
			}
		case globals.LdapSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != globals.LdapSubtype.String() {
				badFields[typeField] = "Doesn't match the parent resource's type."
			}
			attrs := req.GetItem().GetLdapAccountAttributes()
			switch {
			case attrs == nil:
				badFields["attributes"] = "This is a required field."
			default:
				if attrs.GetLoginName() == "" {
					badFields[loginAttrField] = "This is a required field for this type."
				}
				if attrs.GetFullName() != "" {
					badFields[nameAttrField] = "This is a read only field."
				}
				if attrs.GetEmail() != "" {
					badFields[emailAttrField] = "This is a read only field."
				}
				if attrs.GetDn() != "" {
					badFields[dnAttrField] = "This is a read only field."
				}
				if len(attrs.GetMemberOfGroups()) > 0 {
					badFields[memberOfAttrField] = "This is a read only field."
				}
			}
		default:
			badFields[authMethodIdField] = "Unknown auth method type from ID."
		}
		return badFields
	})
}

func validateUpdateRequest(ctx context.Context, req *pbs.UpdateAccountRequest) error {
	const op = "accounts.validateUpdateRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch subtypes.SubtypeFromId(domain, req.GetId()) {
		case globals.PasswordSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != globals.PasswordSubtype.String() {
				badFields[typeField] = "Cannot modify the resource type."
			}
		case globals.OidcSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != globals.OidcSubtype.String() {
				badFields[typeField] = "Cannot modify the resource type."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), subjectField) {
				badFields[subjectField] = "Field cannot be updated."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), issuerField) {
				badFields[issuerField] = "Field cannot be updated."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), emailClaimField) {
				badFields[emailClaimField] = "Field is read only."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), nameClaimField) {
				badFields[nameClaimField] = "Field is read only."
			}
		case globals.LdapSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != globals.LdapSubtype.String() {
				badFields[typeField] = "Cannot modify the resource type."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), loginAttrField) {
				badFields[loginAttrField] = "Field cannot be updated."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), nameAttrField) {
				badFields[nameAttrField] = "Field cannot be updated."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), emailAttrField) {
				badFields[emailAttrField] = "Field cannot be updated."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), dnAttrField) {
				badFields[dnAttrField] = "Field cannot be updated."
			}
			if handlers.MaskContains(req.GetUpdateMask().GetPaths(), memberOfAttrField) {
				badFields[memberOfAttrField] = "Field cannot be updated."
			}
		}
		return badFields
	}, globals.PasswordAccountPreviousPrefix, globals.PasswordAccountPrefix, globals.OidcAccountPrefix, globals.LdapAccountPrefix)
}

func validateDeleteRequest(ctx context.Context, req *pbs.DeleteAccountRequest) error {
	const op = "accounts.validateDeleteRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, globals.PasswordAccountPreviousPrefix, globals.PasswordAccountPrefix, globals.OidcAccountPrefix, globals.LdapAccountPrefix)
}

func validateListRequest(ctx context.Context, req *pbs.ListAccountsRequest) error {
	const op = "accounts.validateListRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetAuthMethodId()), globals.PasswordAuthMethodPrefix, globals.OidcAuthMethodPrefix, globals.LdapAuthMethodPrefix) {
		badFields[authMethodIdField] = "Invalid formatted identifier."
	}
	if _, err := handlers.NewFilter(ctx, req.GetFilter()); err != nil {
		badFields[filterField] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateChangePasswordRequest(ctx context.Context, req *pbs.ChangePasswordRequest) error {
	const op = "accounts.validateChangePasswordRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.PasswordAccountPreviousPrefix, globals.PasswordAccountPrefix) {
		badFields[idField] = "Improperly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[versionField] = "Existing resource version is required for an update."
	}
	if req.GetNewPassword() == "" {
		badFields[newPasswordField] = "This is a required field."
	}
	if req.GetCurrentPassword() == "" {
		badFields[currentPasswordField] = "This is a required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateSetPasswordRequest(ctx context.Context, req *pbs.SetPasswordRequest) error {
	const op = "accounts.validateSetPasswordRequest"
	if req == nil {
		return errors.New(ctx, errors.InvalidParameter, op, "nil request")
	}
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), globals.PasswordAccountPreviousPrefix, globals.PasswordAccountPrefix) {
		badFields[idField] = "Improperly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields[versionField] = "Existing resource version is required for an update."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}
