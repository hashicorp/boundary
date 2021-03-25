package accounts

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc"
	oidcstore "github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/auth/password"
	pwstore "github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/accounts"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	// general auth method field names
	versionField      = "version"
	authMethodIdField = "auth_method_id"
	typeField         = "type"
	attributesField   = "attributes"
	filterField = "filter"
	idField = "id"

	// password field names
	loginNameField = "login_name"
	newPasswordField = "new_password"
	currentPasswordField = "current_password"
)

var (
	pwMaskManager handlers.MaskManager
	oidcMaskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = map[auth.SubType]action.ActionSet{
		auth.PasswordSubtype: {
			action.Read,
			action.Update,
			action.Delete,
			action.SetPassword,
			action.ChangePassword,
		},
		auth.OidcSubtype: {
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
	if pwMaskManager, err = handlers.NewMaskManager(&pwstore.Account{}, &pb.Account{}, &pb.PasswordAccountAttributes{}); err != nil {
		panic(err)
	}
	if oidcMaskManager, err = handlers.NewMaskManager(&oidcstore.Account{}, &pb.Account{}, &pb.OidcAccountAttributes{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.AccountServiceServer interface.
type Service struct {
	pbs.UnimplementedAccountServiceServer

	pwRepoFn common.PasswordAuthRepoFactory
	oidcRepoFn common.OidcAuthRepoFactory
}

// NewService returns a user service which handles user related requests to boundary.
func NewService(pwRepo common.PasswordAuthRepoFactory, oidcRepo common.OidcAuthRepoFactory) (Service, error) {
	if pwRepo == nil {
		return Service{}, fmt.Errorf("nil password repository provided")
	}
	if oidcRepo == nil {
		return Service{}, fmt.Errorf("nil oidc repository provided")
	}
	return Service{pwRepoFn: pwRepo, oidcRepoFn: oidcRepo}, nil
}

var _ pbs.AccountServiceServer = Service{}

// ListAccounts implements the interface pbs.AccountServiceServer.
func (s Service) ListAccounts(ctx context.Context, req *pbs.ListAccountsRequest) (*pbs.ListAccountsResponse, error) {
	if err := validateListRequest(req); err != nil {
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
	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.Account, 0, len(ul))
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.Account,
		Pin:     req.GetAuthMethodId(),
	}
	for _, item := range ul {
		item.Scope = authResults.Scope
		item.AuthorizedActions = authResults.FetchActionSetForId(ctx, item.Id, IdActions[auth.SubtypeFromId(item.Id)], auth.WithResource(res)).Strings()
		if len(item.AuthorizedActions) == 0 {
			continue
		}
		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListAccountsResponse{Items: finalItems}, nil
}

// GetAccount implements the interface pbs.AccountServiceServer.
func (s Service) GetAccount(ctx context.Context, req *pbs.GetAccountRequest) (*pbs.GetAccountResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	return &pbs.GetAccountResponse{Item: u}, nil
}

// CreateAccount implements the interface pbs.AccountServiceServer.
func (s Service) CreateAccount(ctx context.Context, req *pbs.CreateAccountRequest) (*pbs.CreateAccountResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetAuthMethodId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.createInRepo(ctx, authMeth.GetPublicId(), authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	return &pbs.CreateAccountResponse{Item: u, Uri: fmt.Sprintf("accounts/%s", u.GetId())}, nil
}

// UpdateAccount implements the interface pbs.AccountServiceServer.
func (s Service) UpdateAccount(ctx context.Context, req *pbs.UpdateAccountRequest) (*pbs.UpdateAccountResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authMeth, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), authMeth.GetPublicId(), req)
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	return &pbs.UpdateAccountResponse{Item: u}, nil
}

// DeleteAccount implements the interface pbs.AccountServiceServer.
func (s Service) DeleteAccount(ctx context.Context, req *pbs.DeleteAccountRequest) (*pbs.DeleteAccountResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
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
	return &pbs.DeleteAccountResponse{}, nil
}

// ChangePassword implements the interface pbs.AccountServiceServer.
func (s Service) ChangePassword(ctx context.Context, req *pbs.ChangePasswordRequest) (*pbs.ChangePasswordResponse, error) {
	if err := validateChangePasswordRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.ChangePassword)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.changePasswordInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetVersion(), req.GetCurrentPassword(), req.GetNewPassword())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	return &pbs.ChangePasswordResponse{Item: u}, nil
}

// SetPassword implements the interface pbs.AccountServiceServer.
func (s Service) SetPassword(ctx context.Context, req *pbs.SetPasswordRequest) (*pbs.SetPasswordResponse, error) {
	if err := validateSetPasswordRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.SetPassword)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.setPasswordInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetVersion(), req.GetPassword())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	u.AuthorizedActions = authResults.FetchActionSetForId(ctx, u.Id, IdActions[auth.SubtypeFromId(u.Id)]).Strings()
	return &pbs.SetPasswordResponse{Item: u}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Account, error) {
	var acct auth.Account
	switch auth.SubtypeFromId(id) {
	case auth.PasswordSubtype:
		repo, err := s.pwRepoFn()
		if err != nil {
			return nil, err
		}
		a, err := repo.LookupAccount(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, handlers.NotFoundErrorf("Account %q doesn't exist.", id)
			}
			return nil, err
		}
		acct = a
	case auth.OidcSubtype:
		repo, err := s.oidcRepoFn()
		if err != nil {
			return nil, err
		}
		a, err := repo.LookupAccount(ctx, id)
		if err != nil {
			if errors.IsNotFoundError(err) {
				return nil, handlers.NotFoundErrorf("Account %q doesn't exist.", id)
			}
			return nil, err
		}
		acct = a
	default:
		return nil, handlers.NotFoundErrorf("Unrecognized id.")
	}
	return toProto(acct)
}

func (s Service) createInRepo(ctx context.Context, authMethodId, scopeId string, item *pb.Account) (*pb.Account, error) {
	pwAttrs := &pb.PasswordAccountAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
			map[string]string{"attributes": "Attribute fields do not match the expected format."})
	}
	opts := []password.Option{password.WithLoginName(pwAttrs.GetLoginName())}
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	a, err := password.NewAccount(authMethodId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build user for creation: %v.", err)
	}
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}

	var createOpts []password.Option
	if pwAttrs.GetPassword() != nil {
		createOpts = append(createOpts, password.WithPassword(pwAttrs.GetPassword().GetValue()))
	}
	out, err := repo.CreateAccount(ctx, scopeId, a, createOpts...)
	if err != nil {
		return nil, fmt.Errorf("unable to create user: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create user but no error returned from repository.")
	}
	return toProto(out)
}

func (s Service) updatePwInRepo(ctx context.Context, scopeId, authMethId, id string, mask []string, item *pb.Account) (*password.Account, error) {
	u, err := toStoragePwAccount(authMethId, item)
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
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAccount(ctx, scopeId, u, version, dbMask)
	if err != nil {
		switch {
		case errors.Match(errors.T(errors.PasswordTooShort), err):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"attributes.login_name": "Length too short."})
		}
		return nil, fmt.Errorf("unable to update auth method: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Account %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}
func (s Service) updateOidcInRepo(ctx context.Context, scopeId, amId, id string, mask []string, item *pb.Account) (*oidc.Account, error) {
	const op = "account_service.(Service).updateOidcInRepo"
	if item == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil account.")
	}
	var opts []oidc.Option
	if item.GetName() != nil {
		opts = append(opts, oidc.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, oidc.WithDescription(item.GetDescription().GetValue()))
	}
	// TODO: Change the signature to not require so many fields when creating a new account.
	u, err := oidc.NewAccount(amId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for creation: %v.", err)
	}

	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for update: %v.", err)
	}
	u.PublicId = id

	version := item.GetVersion()

	dbMask := oidcMaskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAccount(ctx, scopeId, u, version, dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update account: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Account %q doesn't exist or incorrect version provided.", id)
	}
	return out, nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, authMethodId string, req *pbs.UpdateAccountRequest) (*pb.Account, error) {
	var out auth.Account
	switch auth.SubtypeFromId(req.GetId()) {
	case auth.PasswordSubtype:
		a, err := s.updatePwInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, err
		}
		if a == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update account but no error returned from repository.")
		}
		out = a
	case auth.OidcSubtype:
		a, err := s.updateOidcInRepo(ctx, scopeId, authMethodId, req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
		if err != nil {
			return nil, err
		}
		if a == nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to update account but no error returned from repository.")
		}
		out = a
	}
	return toProto(out)
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	var rows int
	var err error
	switch auth.SubtypeFromId(id) {
	case auth.PasswordSubtype:
		repo, iErr := s.pwRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteAccount(ctx, scopeId, id)
	case auth.OidcSubtype:
		repo, iErr := s.oidcRepoFn()
		if iErr != nil {
			return false, iErr
		}
		rows, err = repo.DeleteAccount(ctx, scopeId, id)
	}
	if err != nil {
		if errors.IsNotFoundError(err) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete account: %w", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, authMethodId string) ([]*pb.Account, error) {
	pwRepo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
	}
	pwl, err := pwRepo.ListAccounts(ctx, authMethodId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.Account
	for _, u := range pwl {
		ou, err := toProto(u)
		if err != nil {
			return nil, err
		}
		outUl = append(outUl, ou)
	}
	oidcRepo, err := s.oidcRepoFn()
	if err != nil {
		return nil, err
	}
	oidcl, err := oidcRepo.ListAccounts(ctx, authMethodId)
	if err != nil {
		return nil, err
	}
	for _, u := range oidcl {
		ou, err := toProto(u)
		if err != nil {
			return nil, err
		}
		outUl = append(outUl, ou)
	}
	return outUl, nil
}

func (s Service) changePasswordInRepo(ctx context.Context, scopeId, id string, version uint32, currentPassword, newPassword string) (*pb.Account, error) {
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("unable to change password: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "Failed to change password.")
	}
	return toProto(out)
}

func (s Service) setPasswordInRepo(ctx context.Context, scopeId, id string, version uint32, pw string) (*pb.Account, error) {
	repo, err := s.pwRepoFn()
	if err != nil {
		return nil, err
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
		return nil, fmt.Errorf("unable to set password: %w", err)
	}
	return toProto(out)
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (*password.AuthMethod, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.pwRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var parentId string
	var authMeth *password.AuthMethod
	opts := []auth.Option{auth.WithType(resource.Account), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		acct, err := repo.LookupAccount(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if acct == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		parentId = acct.GetAuthMethodId()
		opts = append(opts, auth.WithId(id))
	}

	authMeth, err = repo.LookupAuthMethod(ctx, parentId)
	if err != nil {
		res.Error = err
		return nil, res
	}
	if authMeth == nil {
		res.Error = handlers.NotFoundError()
		return nil, res
	}
	opts = append(opts, auth.WithScopeId(authMeth.GetScopeId()), auth.WithPin(parentId))
	return authMeth, auth.Verify(ctx, opts...)
}

func toProto(in auth.Account) (*pb.Account, error) {
	out := pb.Account{
		Id:           in.GetPublicId(),
		CreatedTime:  in.GetCreateTime().GetTimestamp(),
		UpdatedTime:  in.GetUpdateTime().GetTimestamp(),
		AuthMethodId: in.GetAuthMethodId(),
		Version:      in.GetVersion(),
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	switch i:= in.(type) {
	case *password.Account:
		out.Type = auth.PasswordSubtype.String()
		st, err := handlers.ProtoToStruct(&pb.PasswordAccountAttributes{LoginName: i.GetLoginName()})
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building password attribute struct: %v", err)
		}
		out.Attributes = st
	case *oidc.Account:
		out.Type = auth.OidcSubtype.String()
		attrs := &pb.OidcAccountAttributes{
			IssuerId:  i.GetIssuerId(),
			SubjectId: i.GetSubjectId(),
			FullName:  i.GetFullName(),
			Email:     i.GetEmail(),
		}
		st, err := handlers.ProtoToStruct(attrs)
		if err != nil {
			return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building oidc attribute struct: %v", err)
		}
		out.Attributes = st
	}
	return &out, nil
}

func toStoragePwAccount(amId string, item *pb.Account) (*password.Account, error) {
	const op = "account_service.toStoragePwAccount"
	if item == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil account.")
	}
	var opts []password.Option
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := password.NewAccount(amId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build account for creation: %v.", err)
	}

	attrs := &pb.PasswordAccountAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), attrs); err != nil {
		return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
			map[string]string{attributesField: "Attribute fields do not match the expected format."})
	}

	if attrs.GetLoginName() != "" {
		u.LoginName = attrs.GetLoginName()
	}
	return u, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAccountRequest) error {
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, password.AccountPrefix, oidc.AccountPrefix)
}

func validateCreateRequest(req *pbs.CreateAccountRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetAuthMethodId() == "" {
			badFields[authMethodIdField] = "This field is required."
		}
		switch auth.SubtypeFromId(req.GetItem().GetAuthMethodId()) {
		case auth.PasswordSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != auth.PasswordSubtype.String() {
				badFields[typeField] = "Doesn't match the parent resource's type."
			}
			pwAttrs := &pb.PasswordAccountAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), pwAttrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			}
			if pwAttrs.GetLoginName() == "" {
				badFields[loginNameField] = "This is a required field for this type."
			}
		default:
			badFields[authMethodIdField] = "Unknown auth method type from ID."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateAccountRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch auth.SubtypeFromId(req.GetId()) {
		case auth.PasswordSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != auth.PasswordSubtype.String() {
				badFields[typeField] = "Cannot modify the resource type."
			}
			pwAttrs := &pb.PasswordAccountAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), pwAttrs); err != nil {
				badFields[attributesField] = "Attribute fields do not match the expected format."
			}
		}
		return badFields
	}, password.AccountPrefix, oidc.AccountPrefix)
}

func validateDeleteRequest(req *pbs.DeleteAccountRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, password.AccountPrefix, oidc.AccountPrefix)
}

func validateListRequest(req *pbs.ListAccountsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetAuthMethodId()), password.AuthMethodPrefix, oidc.AccountPrefix) {
		badFields[authMethodIdField] = "Invalid formatted identifier."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields[filterField] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateChangePasswordRequest(req *pbs.ChangePasswordRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), password.AccountPrefix) {
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

func validateSetPasswordRequest(req *pbs.SetPasswordRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), password.AccountPrefix) {
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
