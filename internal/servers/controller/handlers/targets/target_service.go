package targets

import (
	"context"
	"errors"
	"fmt"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/targets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/store"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.TcpTarget{}, &pb.Target{}, &pb.TcpTargetAttributes{}); err != nil {
		panic(err)
	}
}

// Service handles request as described by the pbs.TargetServiceServer interface.
type Service struct {
	repoFn    common.TargetRepoFactory
	iamRepoFn common.IamRepoFactory
}

// NewService returns a target service which handles target related requests to boundary.
func NewService(repoFn common.TargetRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil target repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{repoFn: repoFn, iamRepoFn: iamRepoFn}, nil
}

var _ pbs.TargetServiceServer = Service{}

// ListTargets implements the interface pbs.TargetServiceServer.
func (s Service) ListTargets(ctx context.Context, req *pbs.ListTargetsRequest) (*pbs.ListTargetsResponse, error) {
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
	return &pbs.ListTargetsResponse{Items: ul}, nil
}

// GetTargets implements the interface pbs.TargetServiceServer.
func (s Service) GetTarget(ctx context.Context, req *pbs.GetTargetRequest) (*pbs.GetTargetResponse, error) {
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
	return &pbs.GetTargetResponse{Item: u}, nil
}

// CreateTarget implements the interface pbs.TargetServiceServer.
func (s Service) CreateTarget(ctx context.Context, req *pbs.CreateTargetRequest) (*pbs.CreateTargetResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.createInRepo(ctx, req.GetItem())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.CreateTargetResponse{Item: u, Uri: fmt.Sprintf("targets/%s", u.GetId())}, nil
}

// UpdateTarget implements the interface pbs.TargetServiceServer.
func (s Service) UpdateTarget(ctx context.Context, req *pbs.UpdateTargetRequest) (*pbs.UpdateTargetResponse, error) {
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
	return &pbs.UpdateTargetResponse{Item: u}, nil
}

// DeleteTarget implements the interface pbs.TargetServiceServer.
func (s Service) DeleteTarget(ctx context.Context, req *pbs.DeleteTargetRequest) (*pbs.DeleteTargetResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	_, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return nil, nil
}

// AddTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) AddTargetHostSets(ctx context.Context, req *pbs.AddTargetHostSetsRequest) (*pbs.AddTargetHostSetsResponse, error) {
	if err := validateAddRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.AddHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.addInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.AddTargetHostSetsResponse{Item: u}, nil
}

// SetTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) SetTargetHostSets(ctx context.Context, req *pbs.SetTargetHostSetsRequest) (*pbs.SetTargetHostSetsResponse, error) {
	if err := validateSetRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.SetHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.setInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.SetTargetHostSetsResponse{Item: u}, nil
}

// RemoveTargetHostSets implements the interface pbs.TargetServiceServer.
func (s Service) RemoveTargetHostSets(ctx context.Context, req *pbs.RemoveTargetHostSetsRequest) (*pbs.RemoveTargetHostSetsResponse, error) {
	if err := validateRemoveRequest(req); err != nil {
		return nil, err
	}
	authResults := s.authResult(ctx, req.GetId(), action.RemoveHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	u, err := s.removeInRepo(ctx, req.GetId(), req.GetHostSetIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	u.Scope = authResults.Scope
	return &pbs.RemoveTargetHostSetsResponse{Item: u}, nil
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
	return toProto(u, m)
}

func (s Service) createInRepo(ctx context.Context, item *pb.Target) (*pb.Target, error) {
	opts := []target.Option{target.WithName(item.GetName().GetValue())}
	if item.GetDescription() != nil {
		opts = append(opts, target.WithDescription(item.GetDescription().GetValue()))
	}
	tcpAttrs := &pb.TcpTargetAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), tcpAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if tcpAttrs.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(tcpAttrs.GetDefaultPort().GetValue()))
	}
	u, err := target.NewTcpTarget(item.GetScopeId(), opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build target for creation: %v.", err)
	}
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, err := repo.CreateTcpTarget(ctx, u)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create target: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create target but no error returned from repository.")
	}
	return toProto(out, m)
}

func (s Service) updateInRepo(ctx context.Context, scopeId, id string, mask []string, item *pb.Target) (*pb.Target, error) {
	var opts []target.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, target.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, target.WithName(name.GetValue()))
	}

	tcpAttrs := &pb.TcpTargetAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), tcpAttrs); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "Provided attributes don't match expected format.")
	}
	if tcpAttrs.GetDefaultPort().GetValue() != 0 {
		opts = append(opts, target.WithDefaultPort(tcpAttrs.GetDefaultPort().GetValue()))
	}
	version := item.GetVersion()
	u, err := target.NewTcpTarget(scopeId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build target for update: %v.", err)
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
		return nil, status.Errorf(codes.Internal, "Unable to update target: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Target %q doesn't exist.", id)
	}
	return toProto(out, m)
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
		return false, status.Errorf(codes.Internal, "Unable to delete target: %v.", err)
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
		o, err := toProto(u, nil)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "Unable to convert value to proto: %v.", err)
		}
		outUl = append(outUl, o)
	}
	return outUl, nil
}

func (s Service) addInRepo(ctx context.Context, targetId string, hostSetId []string, version uint32) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	out, m, err := repo.AddTargetHostSets(ctx, targetId, version, hostSetId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to add host sets to target: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup target after adding host sets to it.")
	}
	return toProto(out, m)
}

func (s Service) setInRepo(ctx context.Context, targetId string, hostSetIds []string, version uint32) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, _, err = repo.SetTargetHostSets(ctx, targetId, version, hostSetIds)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to set host sets in target: %v.", err)
	}

	out, m, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up target: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup target after setting host sets for it.")
	}
	return toProto(out, m)
}

func (s Service) removeInRepo(ctx context.Context, targetId string, hostSetIds []string, version uint32) (*pb.Target, error) {
	repo, err := s.repoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.DeleteTargeHostSets(ctx, targetId, version, hostSetIds)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to remove host sets from target: %v.", err)
	}
	out, m, err := repo.LookupTarget(ctx, targetId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up target: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup target after removing host sets from it.")
	}
	return toProto(out, m)
}

func (s Service) authResult(ctx context.Context, id string, a action.Type) auth.VerifyResults {
	res := auth.VerifyResults{}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Target), auth.WithAction(a)}
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
		t, _, err := repo.LookupTarget(ctx, id)
		if err != nil {
			res.Error = err
			return res
		}
		if t == nil {
			res.Error = handlers.NotFoundError()
			return res
		}
		parentId = t.GetScopeId()
		opts = append(opts, auth.WithId(id))
	}
	opts = append(opts, auth.WithScopeId(parentId))
	return auth.Verify(ctx, opts...)
}

func toProto(in target.Target, m []*target.TargetSet) (*pb.Target, error) {
	out := pb.Target{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
		Type:        target.TcpTargetType.String(),
	}
	if in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	attrs := &pb.TcpTargetAttributes{}
	if in.GetDefaultPort() > 0 {
		attrs.DefaultPort = &wrappers.UInt32Value{Value: in.GetDefaultPort()}
	}
	st, err := handlers.ProtoToStruct(attrs)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed building password attribute struct: %v", err)
	}
	out.Attributes = st
	for _, hs := range m {
		out.HostSetIds = append(out.HostSetIds, hs.GetPublicId())
		out.HostSets = append(out.HostSets, &pb.HostSet{
			Id:            hs.GetPublicId(),
			HostCatalogId: hs.GetCatalogId(),
		})
	}
	return &out, nil
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
		if !handlers.ValidId(scope.Project.Prefix(), req.GetItem().GetScopeId()) {
			badFields["scope_id"] = "This field is required to have a properly formatted project scope id."
		}
		if req.GetItem().GetName() == nil || req.GetItem().GetName().GetValue() == "" {
			badFields["name"] = "This field is required."
		}
		switch target.SubtypeFromType(req.GetItem().GetType()) {
		case target.TcpSubType:
			tcpAttrs := &pb.TcpTargetAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), tcpAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
			if tcpAttrs.GetDefaultPort() != nil && tcpAttrs.GetDefaultPort().GetValue() == 0 {
				badFields["attributes.default_port"] = "This optional field cannot be set to 0."
			}
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
		if handlers.MaskContains(req.GetUpdateMask().GetPaths(), "name") && req.GetItem().GetName().GetValue() == "" {
			badFields["name"] = "This field cannot be set to empty."
		}
		switch target.SubtypeFromType(req.GetItem().GetType()) {

		case target.TcpSubType:
			tcpAttrs := &pb.TcpTargetAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), tcpAttrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
			if tcpAttrs.GetDefaultPort() != nil && tcpAttrs.GetDefaultPort().GetValue() == 0 {
				badFields["attributes.default_port"] = "This optional field cannot be set to 0."
			}
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
	if !handlers.ValidId(scope.Project.Prefix(), req.GetScopeId()) {
		badFields["scope_id"] = "This field is required to have a properly formatted project scope id."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRequest(req *pbs.AddTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(target.TcpTargetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostSetIds()) == 0 {
		badFields["host_set_ids"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRequest(req *pbs.SetTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(target.TcpTargetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRequest(req *pbs.RemoveTargetHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(target.TcpTargetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostSetIds()) == 0 {
		badFields["host_set_ids"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
