package authmethods

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/auth/password/store"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/authmethods"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.AuthMethod{}, &pb.AuthMethod{}, &pb.PasswordAuthMethodAttributes{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.AuthMethodServiceServer interface.
type Service struct {
	repoFn    common.PasswordAuthRepoFactory
	iamRepoFn common.IamRepoFactory
}

// NewService returns a auth method service which handles auth method related requests to boundary.
func NewService(repo common.PasswordAuthRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil password repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repo, iamRepoFn: iamRepoFn}, nil
}

var _ pbs.AuthMethodServiceServer = Service{}

// ListAuthMethods implements the interface pbs.AuthMethodServiceServer.
func (s Service) ListAuthMethods(ctx context.Context, req *pbs.ListAuthMethodsRequest) (*pbs.ListAuthMethodsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetScopeId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ul, err := s.listFromRepo(ctx, authResults.Scope.GetId())
	if err != nil {
		return nil, err
	}
	for _, item := range ul {
		item.Scope = authResults.Scope
	}
	return &pbs.ListAuthMethodsResponse{Items: ul}, nil
}

// GetAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) GetAuthMethod(ctx context.Context, req *pbs.GetAuthMethodRequest) (*pbs.GetAuthMethodResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.GetAuthMethodResponse{Item: u}, nil
}

// CreateAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) CreateAuthMethod(ctx context.Context, req *pbs.CreateAuthMethodRequest) (*pbs.CreateAuthMethodResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.CreateAuthMethodResponse{Item: u, Uri: fmt.Sprintf("auth-methods/%s", u.GetId())}, nil
}

// UpdateAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) UpdateAuthMethod(ctx context.Context, req *pbs.UpdateAuthMethodRequest) (*pbs.UpdateAuthMethodResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.UpdateAuthMethodResponse{Item: u}, nil
}

// DeleteAuthMethod implements the interface pbs.AuthMethodServiceServer.
func (s Service) DeleteAuthMethod(ctx context.Context, req *pbs.DeleteAuthMethodRequest) (*pbs.DeleteAuthMethodResponse, error) {
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
	return &pbs.DeleteAuthMethodResponse{}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.AuthMethod, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, err := repo.LookupAuthMethod(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("AuthMethod %q doesn't exist.", id)
	}
	return toProto(u)
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.AuthMethod, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListAuthMethods(ctx, scopeId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.AuthMethod
	for _, u := range ul {
		ou, err := toProto(u)
		if err != nil {
			return nil, err
		}
		outUl = append(outUl, ou)
	}
	return outUl, nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.AuthMethod) (*pb.AuthMethod, error) {
	var opts []password.Option
	if item.GetName() != nil {
		opts = append(opts, password.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, password.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := password.NewAuthMethod(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateAuthMethod(ctx, u)
	if err != nil {
		return nil, fmt.Errorf("unable to create auth method: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create auth method but no error returned from repository.")
	}
	return toProto(out)
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.AuthMethod) (*pb.AuthMethod, error) {
	var opts []password.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, password.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, password.WithName(name.GetValue()))
	}
	u, err := password.NewAuthMethod(scopeId, opts...)
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build auth method for update: %v.", err)
	}

	pwAttrs := &pb.PasswordAuthMethodAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), pwAttrs); err != nil {
		return nil, handlers.InvalidArgumentErrorf("Error in provided request.",
			map[string]string{"attributes": "Attribute fields do not match the expected format."})
	}
	if pwAttrs.GetMinLoginNameLength() != 0 {
		u.MinLoginNameLength = pwAttrs.GetMinLoginNameLength()
	}
	if pwAttrs.GetMinPasswordLength() != 0 {
		u.MinPasswordLength = pwAttrs.GetMinPasswordLength()
	}
	version := item.GetVersion()

	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateAuthMethod(ctx, u, version, dbMask)
	if err != nil {
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
	rows, err := repo.DeleteAuthMethod(ctx, scopeId, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, fmt.Errorf("unable to delete auth method: %w", err)
	}
	return rows > 0, nil
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.AuthMethod), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
		iamRepo, err := s.iamRepoFn()
		if err != nil {
			res.Error = err
			return res
		}
		scp, err := iamRepo.LookupScope(ctx, parentId)
		if err != nil {
			res.Error = err
			return res
		}
		if scp == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
	default:
		repo, err := s.repoFn()
		if err != nil {
			res.Error = err
			return res
		}
		authMeth, err := repo.LookupAuthMethod(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if authMeth == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = authMeth.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(in *password.AuthMethod) (*pb.AuthMethod, error) {
	out := pb.AuthMethod{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
		Type:        auth.PasswordSubtype.String(),
	}
	if in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	st, err := handlers.ProtoToStruct(&pb.PasswordAuthMethodAttributes{
		MinLoginNameLength: in.GetMinLoginNameLength(),
		MinPasswordLength:  in.GetMinPasswordLength(),
	})
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "failed building password attribute struct: %v", err)
	}
	out.Attributes = st
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetAuthMethodRequest) error {
	return handlers.ValidateGetRequest(password.AuthMethodPrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateAuthMethodRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(scope.Org.Prefix(), req.GetItem().GetScopeId()) &&
			scope.Global.String() != req.GetItem().GetScopeId() {
			badFields["scope_id"] = "This field must be 'global' or a valid org scope id."
		}
		switch auth.SubtypeFromType(req.GetItem().GetType()) {
		case auth.PasswordSubtype:
			pwAttrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), pwAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
		default:
			badFields["type"] = fmt.Sprintf("This is a required field and must be %q.", auth.PasswordSubtype.String())
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateAuthMethodRequest) error {
	return handlers.ValidateUpdateRequest(password.AuthMethodPrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch auth.SubtypeFromId(req.GetId()) {
		case auth.PasswordSubtype:
			if req.GetItem().GetType() != "" && auth.SubtypeFromType(req.GetItem().GetType()) != auth.PasswordSubtype {
				badFields["type"] = "Cannot modify the resource type."
			}
			pwAttrs := &pb.PasswordAuthMethodAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), pwAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
		default:
			badFields["id"] = "Incorrectly formatted identifier."
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteAuthMethodRequest) error {
	return handlers.ValidateDeleteRequest(password.AuthMethodPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListAuthMethodsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(scope.Org.Prefix(), req.GetScopeId()) &&
		req.GetScopeId() != scope.Global.String() {
		badFields["scope_id"] = "This field must be 'global' or a valid org scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
