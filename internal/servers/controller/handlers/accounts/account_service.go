package accounts

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/watchtower/internal/auth"
	"github.com/hashicorp/watchtower/internal/auth/password"
	"github.com/hashicorp/watchtower/internal/auth/password/store"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/auth"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
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
	if maskManager, err = handlers.NewMaskManager(&pb.Account{}, &store.Account{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.AccountServiceServer interface.
type Service struct {
	repoFn func() (*password.Repository, error)
}

// NewService returns a user service which handles user related requests to watchtower.
func NewService(repo func() (*password.Repository, error)) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil password repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.AuthAccountServiceServer = Service{}

// ListAuthAccounts implements the interface pbs.AuthAccountServiceServer.
func (s Service) ListAuthAccounts(ctx context.Context, req *pbs.ListAuthAccountsRequest) (*pbs.ListAuthAccountsResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	ul, err := s.listFromRepo(ctx, authResults.Scope.GetId())
	if err != nil {
		return nil, err
	}
	for _, item := range ul {
		item.Scope = authResults.Scope
	}
	return &pbs.ListAuthAccountsResponse{Items: ul}, nil
}

// GetAuthAccounts implements the interface pbs.AuthAccountServiceServer.
func (s Service) GetAuthAccount(ctx context.Context, req *pbs.GetAuthAccountRequest) (*pbs.GetAuthAccountResponse, error) {
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
	return &pbs.GetAuthAccountResponse{Item: u}, nil
}

// CreateAuthAccount implements the interface pbs.AuthAccountServiceServer.
func (s Service) CreateAuthAccount(ctx context.Context, req *pbs.CreateAuthAccountRequest) (*pbs.CreateAuthAccountResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.CreateAuthAccountResponse{Item: u, Uri: fmt.Sprintf("scopes/%s/users/%s", authResults.Scope.GetId(), u.GetId())}, nil
}

// UpdateAuthAccount implements the interface pbs.AuthAccountServiceServer.
func (s Service) UpdateAuthAccount(ctx context.Context, req *pbs.UpdateAuthAccountRequest) (*pbs.UpdateAuthAccountResponse, error) {
	panic("UpdateAuthAccount is not implemented.")
}

// DeleteAuthAccount implements the interface pbs.AuthAccountServiceServer.
func (s Service) DeleteAuthAccount(ctx context.Context, req *pbs.DeleteAuthAccountRequest) (*pbs.DeleteAuthAccountResponse, error) {
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
	return &pbs.DeleteAuthAccountResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Account, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, err := repo.LookupAccount(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("AuthAccount %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("AuthAccount %q doesn't exist.", id)
	}
	return toProto(u), nil
}

func (s Service) createInRepo(ctx context.Context, authMethodId string, item *pb.Account) (*pb.Account, error) {
	pwAttrs := &pb.PasswordAccountAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	var opts []password.Option
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	a, err := password.NewAccount(authMethodId, pwAttrs.GetUsername(), opts...)
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
	return toProto(out), nil
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

func (s Service) listFromRepo(ctx context.Context, orgId string) ([]*pb.Account, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListAccounts(ctx, orgId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.Account
	for _, u := range ul {
		outUl = append(outUl, toProto(u))
	}
	return outUl, nil
}

func toProto(in *password.Account) *pb.Account {
	out := pb.Account{
		Id:          in.GetPublicId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAuthAccountRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), password.AccountPrefix+"_") {
		badFields["id"] = "Invalid formatted user id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateAuthAccountRequest) error {
	badFields := map[string]string{}
	item := req.GetItem()
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field."
	}
	switch item.GetType() {
	case "password":
		if err := handlers.StructToProto(item.GetAttributes(), &pb.PasswordAccountAttributes{}); err != nil {
			badFields["attributes"] = "Attribute fields do not match the expected format."
		}
	default:
		badFields["type"] = "This is a required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Argument errors found in the request.", badFields)
	}
	return nil
}

func validateDeleteRequest(req *pbs.DeleteAuthAccountRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), password.AccountPrefix+"_") {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateListRequest(req *pbs.ListAuthAccountsRequest) error {
	badFields := map[string]string{}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
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
