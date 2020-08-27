package targets

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.TcpTarget{}, &pb.Target{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.TargetServiceServer interface.
type Service struct {
	repoFn func() (*target.Repository, error)
}

// NewService returns a user service which handles user related requests to boundary.
func NewService(repo func() (*target.Repository, error)) (Service, error) {
	if repo == nil {
		return Service{}, fmt.Errorf("nil target repository provided")
	}
	return Service{repoFn: repo}, nil
}

var _ pbs.TargetServiceServer = Service{}

// ListTargets implements the interface pbs.TargetServiceServer.
func (s Service) ListTargets(ctx context.Context, req *pbs.ListTargetsRequest) (*pbs.ListTargetsResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
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
	return &pbs.ListTargetsResponse{Items: ul}, nil
}

// GetTargets implements the interface pbs.TargetServiceServer.
func (s Service) GetTarget(ctx context.Context, req *pbs.GetTargetRequest) (*pbs.GetTargetResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	u, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.GetTargetResponse{Item: u}, nil
}

// CreateTarget implements the interface pbs.TargetServiceServer.
func (s Service) CreateTarget(ctx context.Context, req *pbs.CreateTargetRequest) (*pbs.CreateTargetResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.CreateTargetResponse{Item: u, Uri: fmt.Sprintf("scopes/%s/targets/%s", authResults.Scope.GetId(), u.GetId())}, nil
}

// UpdateTarget implements the interface pbs.TargetServiceServer.
func (s Service) UpdateTarget(ctx context.Context, req *pbs.UpdateTargetRequest) (*pbs.UpdateTargetResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	u, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.UpdateTargetResponse{Item: u}, nil
}

// DeleteTarget implements the interface pbs.TargetServiceServer.
func (s Service) DeleteTarget(ctx context.Context, req *pbs.DeleteTargetRequest) (*pbs.DeleteTargetResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteTargetResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	u, m, err := repo.LookupTarget(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
		}
		return nil, err
	}
	if u == nil {
		return nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
	}
	return toProto(u, m), nil
}

func (s Service) createInRepo(ctx context.Context, scopeId string, item *pb.Target) (*pb.Target, error) {
	opts := []target.Option{target.WithName(item.GetName().GetValue())}
	if item.GetDescription() != nil {
		opts = append(opts, target.WithDescription(item.GetDescription().GetValue()))
	}
	u, err := target.NewTcpTarget(scopeId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build user for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, err := repo.CreateTcpTarget(ctx, u)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create user: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create user but no error returned from repository.")
	}
	return toProto(out, m), nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Target) (*pb.Target, error) {
	var opts []target.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, target.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, target.WithName(name.GetValue()))
	}
	version := item.GetVersion()
	u, err := target.NewTcpTarget(scopeId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build user for update: %v.", err)
	}
	u.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, rowsUpdated, err := repo.UpdateTcpTarget(ctx, u, version, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update user: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
	}
	return toProto(out, m), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.repoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteTarget(ctx, id)
	if err != nil {
		if errors.Is(err, db.ErrRecordNotFound) {
			return false, nil
		}
		return false, status.Errorf(codes.Internal, "Unable to delete user: %v.", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListTargets(ctx, target.WithScopeId(scopeId))
	if err != nil {
		return nil, err
	}
	var outUl []*pb.Target
	for _, u := range ul {
		outUl = append(outUl, toProto(u, nil))
	}
	return outUl, nil
}

func toProto(in target.Target, m []*target.TargetSet) *pb.Target {
	out := pb.Target{
		Id:          in.GetPublicId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
		Type:        target.TcpTargetType.String(),
	}
	if in.GetDescription() != "" {
		out.Description = &wrapperspb.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrapperspb.StringValue{Value: in.GetName()}
	}
	for _, hs := range m {
		out.HostSetIds = append(out.HostSetIds, hs.GetPublicId())
		out.HostSets = append(out.HostSets, &pb.HostSet{
			Id:            hs.GetPublicId(),
			HostCatalogId: hs.GetCatalogId(),
		})
	}
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetRequest(req *pbs.GetTargetRequest) error {
	return handlers.ValidateGetRequest(target.TcpTargetPrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateTargetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetName() == nil || req.GetItem().GetName().GetValue() == "" {
			badFields["name"] = "This field is required."
		}
		switch req.GetItem().GetType() {
		case target.TcpTargetType.String():
		case "":
			badFields["type"] = "This is a required field."
		default:
			badFields["type"] = "Unknown type provided."
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateTargetRequest) error {
	return handlers.ValidateUpdateRequest(target.TcpTargetPrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetName() != nil && req.GetItem().GetName().GetValue() == "" {
			badFields["name"] = "This field cannot be set to empty."
		}
		if req.GetItem().GetType() != "" {
			badFields["type"] = "This field cannot be updated."
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteTargetRequest) error {
	return handlers.ValidateDeleteRequest(target.TcpTargetPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListTargetsRequest) error {
	badFields := map[string]string{}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
