package accounts

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/accounts"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.Account{}, &pb.Account{}, &pb.PasswordAccountAttributes{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.AccountServiceServer interface.
type Service struct {
	repoFn common.PasswordAuthRepoFactory
}

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo common.PasswordAuthRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil password repository provided")
	}
	return Service{repoFn: repo}, nil
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
	for _, item := range ul {
		item.Scope = authResults.Scope
	}
	return &pbs.ListAccountsResponse{Items: ul}, nil
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
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), authMeth.GetPublicId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
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
	return &pbs.SetPasswordResponse{Item: u}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Account, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, err := repo.LookupAccount(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Account %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("Account %q doesn't exist.", id)
	}
	return toProto(u)
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
	repo, err := s.repoFn()
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

func (s Service) updateInRepo(ctx context.Context, scopeId, authMethId, id string, mask []string, item *pb.Account) (*pb.Account, error) {
	var opts []password.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, password.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, password.WithName(name.GetValue()))
	}
	u, err := password.NewAccount(authMethId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for update: %v.", err)
	}
	u.PublicId = id

	pwAttrs := &pb.PasswordAccountAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if pwAttrs.GetLoginName() != "" {
		u.LoginName = pwAttrs.GetLoginName()
	}
	version := item.GetVersion()

	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAccount(ctx, scopeId, u, version, dbMask)
	if err != nil {
		switch {
		case errors.Is(err, password.ErrTooShort):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"attributes.login_name": "Length too short."})
		}
		return nil, fmt.Errorf("unable to update auth method: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist or incorrect version provided.", id)
	}
	return toProto(out)
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteAccount(ctx, scopeId, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete account: %w", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, authMethodId string) ([]*pb.Account, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListAccounts(ctx, authMethodId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.Account
	for _, u := range ul {
		ou, err := toProto(u)
		if err != nil {
			return nil, err
		}
		outUl = append(outUl, ou)
	}
	return outUl, nil
}

func (s Service) changePasswordInRepo(ctx context.Context, scopeId, id string, version uint32, currentPassword, newPassword string) (*pb.Account, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.ChangePassword(ctx, scopeId, id, currentPassword, newPassword, version)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrRecordNotFound):
			return nil, handlers.NotFoundErrorf("Account not found.")
		case errors.Is(err, password.ErrTooShort):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"new_password": "Password is too short."})
		case errors.Is(err, password.ErrPasswordsEqual):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"new_password": "New password equal to current password."})
		}
		return nil, fmt.Errorf( "unable to change password: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.PermissionDenied, "Failed to change password.")
	}
	return toProto(out)
}

func (s Service) setPasswordInRepo(ctx context.Context, scopeId, id string, version uint32, pw string) (*pb.Account, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.SetPassword(ctx, scopeId, id, pw, version)
	if err != nil {
		switch {
		case errors.Is(err, db.ErrRecordNotFound):
			return nil, handlers.NotFoundErrorf("Account not found.")
		case errors.Is(err, password.ErrTooShort):
			return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
				map[string]string{"password": "Password is too short."})
		}
		return nil, fmt.Errorf("unable to set password: %w", err)
	}
	return toProto(out)
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (*password.AuthMethod, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.repoFn()
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

func toProto(in *password.Account) (*pb.Account, error) {
	out := pb.Account{
		Id:           in.GetPublicId(),
		CreatedTime:  in.GetCreateTime().GetTimestamp(),
		UpdatedTime:  in.GetUpdateTime().GetTimestamp(),
		AuthMethodId: in.GetAuthMethodId(),
		Version:      in.GetVersion(),
		Type:         auth.PasswordSubtype.String(),
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	if st, err := handlers.ProtoToStruct(&pb.PasswordAccountAttributes{LoginName: in.GetLoginName()}); err == nil {
		out.Attributes = st
	} else {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building password attribute struct: %v", err)
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAccountRequest) error {
	return handlers.ValidateGetRequest(password.AccountPrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateAccountRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetAuthMethodId() == "" {
			badFields["auth_method_id"] = "This field is required."
		}
		switch auth.SubtypeFromId(req.GetItem().GetAuthMethodId()) {
		case auth.PasswordSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != auth.PasswordSubtype.String() {
				badFields["type"] = "Doesn't match the parent resource's type."
			}
			pwAttrs := &pb.PasswordAccountAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), pwAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
			if pwAttrs.GetLoginName() == "" {
				badFields["login_name"] = "This is a required field for this type."
			}
		default:
			badFields["auth_method_id"] = "Unknown auth method type from ID."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateAccountRequest) error {
	return handlers.ValidateUpdateRequest(password.AccountPrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch auth.SubtypeFromId(req.GetId()) {
		case auth.PasswordSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != auth.PasswordSubtype.String() {
				badFields["type"] = "Cannot modify the resource type."
			}
			pwAttrs := &pb.PasswordAccountAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), pwAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteAccountRequest) error {
	return handlers.ValidateDeleteRequest(password.AccountPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListAccountsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(password.AuthMethodPrefix, req.GetAuthMethodId()) {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateChangePasswordRequest(req *pbs.ChangePasswordRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(password.AccountPrefix, req.GetId()) {
		badFields["id"] = "Improperly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Existing resource version is required for an update."
	}
	if req.GetNewPassword() == "" {
		badFields["new_password"] = "This is a required field."
	}
	if req.GetCurrentPassword() == "" {
		badFields["current_password"] = "This is a required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}

func validateSetPasswordRequest(req *pbs.SetPasswordRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(password.AccountPrefix, req.GetId()) {
		badFields["id"] = "Improperly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Existing resource version is required for an update."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Error in provided request.", badFields)
	}
	return nil
}
