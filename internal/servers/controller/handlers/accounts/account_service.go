package accounts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.Account{}, &pb.Account{}, &pb.PasswordAccountAttributes{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.AccountServiceServer interface.
type Service struct {
	repoFn func() (*password.Repository, error)
}

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo func() (*password.Repository, error)) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil password repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.AccountServiceServer = Service{}

// TODO(ICU-407): Validate that the provided auth method and account are in the provided scope.

// ListAccounts implements the interface pbs.AccountServiceServer.
func (s Service) ListAccounts(ctx context.Context, req *pbs.ListAccountsRequest) (*pbs.ListAccountsResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateListRequest(req); err != nil {
		return nil, err
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

// GetAccounts implements the interface pbs.AccountServiceServer.
func (s Service) GetAccount(ctx context.Context, req *pbs.GetAccountRequest) (*pbs.GetAccountResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateGetRequest(req); err != nil {
		return nil, err
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
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.createInRepo(ctx, req.GetAuthMethodId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.CreateAccountResponse{Item: u, Uri: fmt.Sprintf("scopes/%s/auth-methods/%s/accounts/%s", authResults.Scope.GetId(), u.GetAuthMethodId(), u.GetId())}, nil
}

// UpdateAccount implements the interface pbs.AccountServiceServer.
func (s Service) UpdateAccount(ctx context.Context, req *pbs.UpdateAccountRequest) (*pbs.UpdateAccountResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.updateInRepo(ctx, req.GetAuthMethodId(), req.GetId(), req.GetVersion(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.UpdateAccountResponse{Item: u}, nil
}

// DeleteAccount implements the interface pbs.AccountServiceServer.
func (s Service) DeleteAccount(ctx context.Context, req *pbs.DeleteAccountRequest) (*pbs.DeleteAccountResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteAccountResponse{Existed: existed}, nil
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

func (s Service) createInRepo(ctx context.Context, authMethodId string, item *pb.Account) (*pb.Account, error) {
	pwAttrs := &pb.PasswordAccountAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	opts := []password.Option{password.WithLoginName(pwAttrs.GetLoginName())}
	if pwAttrs.GetPassword() != nil {
		opts = append(opts, password.WithPassword(pwAttrs.GetPassword().GetValue()))
	}
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	a, err := password.NewAccount(authMethodId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build user for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateAccount(ctx, a)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create user: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create user but no error returned from repository.")
	}
	return toProto(out)
}

func (s Service) updateInRepo(ctx context.Context, authMethodId, id string, version uint32, mask []string, item *pb.Account) (*pb.Account, error) {
	var opts []password.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, password.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, password.WithName(name.GetValue()))
	}
	u, err := password.NewAccount(authMethodId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build auth method for update: %v.", err)
	}
	u.PublicId = id

	pwAttrs := &pb.PasswordAccountAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if pwAttrs.GetLoginName() != "" {
		u.LoginName = pwAttrs.GetLoginName()
	}

	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAccount(ctx, u, version, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update auth method: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
	}
	return toProto(out)
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteAccount(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "Unable to delete user: %v.", err)
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

func toProto(in *password.Account) (*pb.Account, error) {
	out := pb.Account{
		Id:           in.GetPublicId(),
		CreatedTime:  in.GetCreateTime().GetTimestamp(),
		UpdatedTime:  in.GetUpdateTime().GetTimestamp(),
		AuthMethodId: in.GetAuthMethodId(),
		Version:      in.GetVersion(),
		Type:         "password",
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
		return nil, status.Errorf(codes.Internal, "failed building password attribute struct: %v", err)
	}
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAccountRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), password.AccountPrefix+"_") {
		badFields["id"] = "Invalid formatted identifier."
	}
	if !validId(req.GetAuthMethodId(), password.AuthMethodPrefix+"_") {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateAccountRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetAuthMethodId(), password.AuthMethodPrefix+"_") {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	item := req.GetItem()
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field."
	}
	if item.GetAuthMethodId() != "" {
		badFields["auth_method_id"] = "This is a read only field."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field."
	}
	switch item.GetType() {
	case "password":
		pwAttrs := &pb.PasswordAccountAttributes{}
		if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
			badFields["attributes"] = "Attribute fields do not match the expected format."
		}
		if pwAttrs.GetLoginName() == "" {
			badFields["login_name"] = "This is a required field for this type."
		}
	default:
		badFields["type"] = "This is a required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Argument errors found in the request.", badFields)
	}
	return nil
}

func validateDeleteRequest(req *pbs.DeleteAccountRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetAuthMethodId(), password.AuthMethodPrefix+"_") {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	if !validId(req.GetId(), password.AccountPrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateListRequest(req *pbs.ListAccountsRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetAuthMethodId(), password.AuthMethodPrefix+"_") {
		badFields["auth_method_id"] = "Invalid formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateUpdateRequest(req *pbs.UpdateAccountRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), password.AccountPrefix+"_") {
		badFields["id"] = "Improperly formatted identifier."
	}
	if !validId(req.GetAuthMethodId(), password.AuthMethodPrefix+"_") {
		badFields["auth_method_id"] = "Improperly formatted identifier."
	}
	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "UpdateMask not provided but is required to update this resource."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Existing resource version is required for an update."
	}

	item := req.GetItem()
	if item == nil {
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetAuthMethodId() != "" {
		badFields["auth_method_id"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetType() != "" {
		badFields["type"] = "This is a read only field and cannot be specified in an update request."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}

	return nil
}

func validId(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	id = strings.TrimPrefix(id, prefix)
	return !reInvalidID.Match([]byte(id))
}
