package host_catalogs

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/grpc-ecosystem/grpc-gateway/runtime"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/host/static"
	"github.com/hashicorp/watchtower/internal/host/static/store"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type hostType int

const (
	unknownType hostType = iota
	staticType
)

type hostTypeValidator interface {
	GetId() string
}

func getType(r hostTypeValidator) hostType {
	switch {
	case strings.HasPrefix(r.GetId(), static.HostCatalogPrefix):
		return staticType
	}
	return unknownType
}

var (
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
	// TODO(ICU-28): Find a way to auto update these names and enforce the mappings between wire and storage.
	wireToStorageMask = map[string]string{
		"name":        "Name",
		"description": "Description",
	}
)

type Service struct {
	pbs.UnimplementedHostCatalogServiceServer
	staticRepo *static.Repository
}

func NewService(repo *static.Repository) *Service {
	if repo == nil {
		return nil
	}
	return &Service{staticRepo: repo}
}

var _ pbs.HostCatalogServiceServer = &Service{}

func (s Service) GetHostCatalog(ctx context.Context, req *pbs.GetHostCatalogRequest) (*pbs.GetHostCatalogResponse, error) {
	if err := validateGetHostCatalogRequest(req); err != nil {
		return nil, err
	}
	p, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	resp := &pbs.GetHostCatalogResponse{}
	resp.Item = p
	return resp, nil
}

func (s Service) CreateHostCatalog(ctx context.Context, req *pbs.CreateHostCatalogRequest) (*pbs.CreateHostCatalogResponse, error) {
	if err := validateCreateHostCatalogRequest(req); err != nil {
		return nil, err
	}
	h, err := s.createInRepo(ctx, req.GetProjectId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	resp := &pbs.CreateHostCatalogResponse{}
	resp.Uri = fmt.Sprintf("orgs/%s/projects/%s/host-catalogs/%s", req.GetOrgId(), req.GetProjectId(), h.GetId())
	resp.Item = h
	return resp, nil
}

func (s Service) UpdateHostCatalog(ctx context.Context, req *pbs.UpdateHostCatalogRequest) (*pbs.UpdateHostCatalogResponse, error) {
	if err := validateUpdateHostCatalogRequest(req); err != nil {
		return nil, err
	}
	p, err := s.updateInRepo(ctx, req.GetProjectId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	resp := &pbs.UpdateHostCatalogResponse{}
	resp.Item = p
	return resp, nil
}

func (s Service) DeleteHostCatalog(ctx context.Context, req *pbs.DeleteHostCatalogRequest) (*pbs.DeleteHostCatalogResponse, error) {
	if err := validateDeleteHostCatalogRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	resp := &pbs.DeleteHostCatalogResponse{}
	resp.Existed = existed
	return resp, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.HostCatalog, error) {
	p, err := s.staticRepo.LookupCatalog(ctx, id)
	if err != nil {
		return nil, err
	}
	if p == nil {
		return nil, handlers.NotFoundErrorf("HostCatalog %q doesn't exist.", id)
	}
	return toProto(p), nil
}

func (s Service) createInRepo(ctx context.Context, projId string, item *pb.HostCatalog) (*pb.HostCatalog, error) {
	var opts []static.Option
	if item.GetName() != nil {
		opts = append(opts, static.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, static.WithDescription(item.GetDescription().GetValue()))
	}
	h, err := static.NewHostCatalog(projId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host for creation: %v.", err)
	}
	out, err := s.staticRepo.CreateCatalog(ctx, h)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create host: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create host but no error returned from repository.")
	}
	return toProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, projId, id string, mask []string, item *pb.HostCatalog) (*pb.HostCatalog, error) {
	var opts []static.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, static.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, static.WithName(name.GetValue()))
	}
	h, err := static.NewHostCatalog(projId, opts...)
	h.PublicId = id
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host for update: %v.", err)
	}
	h.PublicId = id
	dbMask, err := toDbUpdateMask(mask)
	if err != nil {
		return nil, err
	}
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", []string{"update_mask"})
	}
	out, rowsUpdated, err := s.staticRepo.UpdateCatalog(ctx, h, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update host: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("HostCatalog %q doesn't exist.", id)
	}
	return toProto(out), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	rows, err := s.staticRepo.DeleteCatalog(ctx, id)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete host: %v.", err)
	}
	return rows > 0, nil
}

// toDbUpdateMask converts the wire format's FieldMask into a list of strings containing FieldMask paths used
func toDbUpdateMask(paths []string) ([]string, error) {
	dbPaths := []string{}
	invalid := []string{}
	for _, p := range paths {
		for _, f := range strings.Split(p, ",") {
			if dbField, ok := wireToStorageMask[strings.TrimSpace(f)]; ok {
				dbPaths = append(dbPaths, dbField)
			} else {
				invalid = append(invalid, f)
			}
		}
	}
	if len(invalid) > 0 {
		return nil, handlers.InvalidArgumentErrorf(fmt.Sprintf("Invalid fields passed in update_update mask: %v.", invalid), []string{"update_mask"})
	}
	return dbPaths, nil
}

type dbHostCatalog interface {
	GetPublicId() string
	GetName() string
	GetDescription() string
	GetCreateTime() *store.Timestamp
	GetUpdateTime() *store.Timestamp
}

func toProto(in dbHostCatalog) *pb.HostCatalog {
	out := pb.HostCatalog{Id: in.GetPublicId()}
	if in.GetDescription() != "" {
		out.Description = &wrappers.StringValue{Value: in.GetDescription()}
	}
	if in.GetName() != "" {
		out.Name = &wrappers.StringValue{Value: in.GetName()}
	}
	out.CreatedTime = in.GetCreateTime().GetTimestamp()
	out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
	return &out
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
func validateGetHostCatalogRequest(req *pbs.GetHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	var badFormat []string
	switch getType(req) {
	case staticType:
		if !validID(req.GetId(), "sthc_") {
			badFormat = append(badFormat, "id")
		}
	default:
		return status.Error(codes.Unimplemented, "No host catalog type identified for provided host catalog prefix.")
	}
	if !validID(req.GetOrgId(), "o_") {
		badFormat = append(badFormat, "org_id")
	}
	if !validID(req.GetProjectId(), "p_") {
		badFormat = append(badFormat, "project_id")
	}
	if len(badFormat) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFormat)
	}
	return nil
}

func validateCreateHostCatalogRequest(req *pbs.CreateHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}

	var badFormat []string
	if !validID(req.GetOrgId(), "o_") {
		badFormat = append(badFormat, "org_id")
	}
	if !validID(req.GetProjectId(), "p_") {
		badFormat = append(badFormat, "project_id")
	}
	if len(badFormat) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFormat)
	}

	item := req.GetItem()
	if item == nil {
		return handlers.InvalidArgumentErrorf("A host's fields must be set to something.", []string{"item"})
	}
	immutableFieldsSet := []string{}
	if item.GetId() != "" {
		immutableFieldsSet = append(immutableFieldsSet, "id")
	}
	if item.GetCreatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "created_time")
	}
	if item.GetUpdatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "updated_time")
	}
	if len(immutableFieldsSet) > 0 {
		return handlers.InvalidArgumentErrorf("Cannot specify read only fields at creation time.", immutableFieldsSet)
	}
	return nil
}

func validateUpdateHostCatalogRequest(req *pbs.UpdateHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	var badFormat []string
	switch getType(req) {
	case staticType:
		if !validID(req.GetId(), "sthc_") {
			badFormat = append(badFormat, "host_catalog")
		}
	default:
		return status.Error(codes.Unimplemented, "No host catalog type identified for provided host catalog prefix.")
	}
	if !validID(req.GetOrgId(), "o_") {
		badFormat = append(badFormat, "org_id")
	}
	if !validID(req.GetProjectId(), "p_") {
		badFormat = append(badFormat, "project_id")
	}
	if len(badFormat) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFormat)
	}

	if req.GetUpdateMask() == nil {
		return handlers.InvalidArgumentErrorf("UpdateMask not provided but is required to update a host.", []string{"update_mask"})
	}

	item := req.GetItem()
	if item == nil {
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if item.GetId() != "" && item.GetId() != req.GetId() {
		return handlers.InvalidArgumentErrorf("Id in provided item and url do not match.", []string{"id"})
	}
	immutableFieldsSet := []string{}
	if item.GetId() != "" {
		immutableFieldsSet = append(immutableFieldsSet, "id")
	}
	if item.GetCreatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "created_time")
	}
	if item.GetUpdatedTime() != nil {
		immutableFieldsSet = append(immutableFieldsSet, "updated_time")
	}
	if len(immutableFieldsSet) > 0 {
		return handlers.InvalidArgumentErrorf("Cannot specify read only fields at update time.", immutableFieldsSet)
	}

	return nil
}

func validateDeleteHostCatalogRequest(req *pbs.DeleteHostCatalogRequest) error {
	if err := validateAncestors(req); err != nil {
		return err
	}
	var badFormat []string
	switch getType(req) {
	case staticType:
		if !validID(req.GetId(), "sthc_") {
			badFormat = append(badFormat, "id")
		}
	default:
		return status.Error(codes.Unimplemented, "No host catalog type identified for provided host catalog prefix.")
	}
	if !validID(req.GetOrgId(), "o_") {
		badFormat = append(badFormat, "org_id")
	}
	if !validID(req.GetProjectId(), "p_") {
		badFormat = append(badFormat, "project_id")
	}
	if len(badFormat) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFormat)
	}
	return nil
}

func validID(id, prefix string) bool {
	if !strings.HasPrefix(id, prefix) {
		return false
	}
	id = strings.TrimPrefix(id, prefix)
	if reInvalidID.Match([]byte(id)) {
		return false
	}
	return true
}

type ancestorProvider interface {
	GetOrgId() string
	GetProjectId() string
}

// validateAncestors verifies that the ancestors of this call are properly set and provided.
func validateAncestors(r ancestorProvider) error {
	if r.GetOrgId() == "" {
		return handlers.InvalidArgumentErrorf("Missing organization id.", []string{"org_id"})
	}
	if r.GetProjectId() == "" {
		return handlers.InvalidArgumentErrorf("Missing project id.", []string{"project_id"})
	}
	return nil
}

// RegisterGrpcGateway satisfies the RegisterGrpcGatewayer interface.
func (s *Service) RegisterGrpcGateway(mux *runtime.ServeMux) error {
	return pbs.RegisterHostCatalogServiceHandlerServer(context.Background(), mux, s)
}
