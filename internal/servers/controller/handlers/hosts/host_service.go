package hosts

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
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
	if maskManager, err = handlers.NewMaskManager(&store.Host{}, &pb.Host{}, &pb.StaticHostAttributes{}); err != nil {
		panic(err)
	}
}

type Service struct {
	staticRepoFn common.StaticRepoFactory
}

var _ pbs.HostServiceServer = Service{}

// NewService returns a host catalog Service which handles host catalog related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn common.StaticRepoFactory) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil static repository provided")
	}
	return Service{staticRepoFn: repoFn}, nil
}

func (s Service) ListHosts(ctx context.Context, req *pbs.ListHostsRequest) (*pbs.ListHostsResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	hl, err := s.listFromRepo(ctx, req.GetHostCatalogId())
	if err != nil {
		return nil, err
	}
	for _, item := range hl {
		item.Scope = authResults.Scope
	}
	return &pbs.ListHostsResponse{Items: hl}, nil
}

// GetHost implements the interface pbs.HostServiceServer.
func (s Service) GetHost(ctx context.Context, req *pbs.GetHostRequest) (*pbs.GetHostResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ct := host.SubtypeFromId(req.GetId())
	if ct == host.UnknownSubtype {
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"id": "Improperly formatted identifier used."})
	}
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	hc, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.GetHostResponse{Item: hc}, nil
}

// CreateHost implements the interface pbs.HostServiceServer.
func (s Service) CreateHost(ctx context.Context, req *pbs.CreateHostRequest) (*pbs.CreateHostResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	h, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetHostCatalogId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	h.Scope = authResults.Scope
	return &pbs.CreateHostResponse{
		Item: h,
		Uri:  fmt.Sprintf("scopes/%s/host-catalogs/%s/hosts/%s", authResults.Scope.GetId(), req.GetHostCatalogId(), h.GetId()),
	}, nil
}

// UpdateHost implements the interface pbs.HostServiceServer.
func (s Service) UpdateHost(ctx context.Context, req *pbs.UpdateHostRequest) (*pbs.UpdateHostResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	ct := host.SubtypeFromId(req.GetId())
	if ct == host.UnknownSubtype {
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"id": "Improperly formatted identifier used."})
	}
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	hc, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetHostCatalogId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.UpdateHostResponse{Item: hc}, nil
}

// DeleteHost implements the interface pbs.HostServiceServer.
func (s Service) DeleteHost(ctx context.Context, req *pbs.DeleteHostRequest) (*pbs.DeleteHostResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, authResults.Scope.GetId(), req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteHostResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.Host, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	h, err := repo.LookupHost(ctx, id)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, handlers.NotFoundErrorf("Host %q doesn't exist.", id)
	}
	return toProto(h, nil)
}

func (s Service) createInRepo(ctx context.Context, scopeId, catalogId string, item *pb.Host) (*pb.Host, error) {
	ha := &pb.StaticHostAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), ha); err != nil {
		return nil, status.Errorf(codes.Internal, "Failed converting attributes to subtype proto: %s", err)
	}
	var opts []static.Option
	if ha.GetAddress() != nil {
		opts = append(opts, static.WithAddress(ha.GetAddress().GetValue()))
	}
	if item.GetName() != nil {
		opts = append(opts, static.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, static.WithDescription(item.GetDescription().GetValue()))
	}
	h, err := static.NewHost(catalogId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host for creation: %v.", err)
	}

	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateHost(ctx, scopeId, h)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create host: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create host but no error returned from repository.")
	}
	return toProto(out, nil)
}

func (s Service) updateInRepo(ctx context.Context, scopeId, catalogId, id string, mask []string, item *pb.Host) (*pb.Host, error) {
	ha := &pb.StaticHostAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), ha); err != nil {
		return nil, status.Errorf(codes.Internal, "Failed converting attributes to subtype proto: %s", err)
	}
	var opts []static.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, static.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, static.WithName(name.GetValue()))
	}
	if addr := ha.GetAddress(); addr != nil {
		opts = append(opts, static.WithAddress(addr.GetValue()))
	}
	h, err := static.NewHost(catalogId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host for update: %v.", err)
	}
	h.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid paths provided in the update mask."})
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateHost(ctx, scopeId, h, item.GetVersion(), dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update host: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Host %q doesn't exist.", id)
	}
	return toProto(out, nil)
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteHost(ctx, scopeId, id)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete host: %v.", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, catalogId string) ([]*pb.Host, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	hl, err := repo.ListHosts(ctx, catalogId)
	if err != nil {
		return nil, err
	}
	var outHl []*pb.Host
	for _, h := range hl {
		p, err := toProto(h, nil)
		if err != nil {
			return nil, err
		}
		outHl = append(outHl, p)
	}
	return outHl, nil
}

func toProto(in *static.Host, members []*static.HostSetMember) (*pb.Host, error) {
	out := pb.Host{
		Id:            in.GetPublicId(),
		HostCatalogId: in.GetCatalogId(),
		Type:          host.StaticSubtype.String(),
		CreatedTime:   in.GetCreateTime().GetTimestamp(),
		UpdatedTime:   in.GetUpdateTime().GetTimestamp(),
		Version:       in.GetVersion(),
	}
	if in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	for _, m := range members {
		out.HostSetIds = append(out.HostSetIds, m.GetSetId())
	}
	st, err := handlers.ProtoToStruct(&pb.StaticHostAttributes{Address: wrapperspb.String(in.GetAddress())})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to convert static attribute to struct: %s", err)
	}
	out.Attributes = st
	return &out, nil
}

// A validateX method should exist for each method above.  These methods do not make calls to any backing service but enforce
// requirements on the structure of the request.  They verify that:
//  * The path passed in is correctly formatted
//  * All required parameters are set
//  * There are no conflicting parameters provided
//  * The type asserted by the ID and/or field is known
//  * If relevant, the type derived from the id prefix matches what is claimed by the type field
func validateGetRequest(req *pbs.GetHostRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetHostCatalogId(), static.HostCatalogPrefix+"_") {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if !validId(req.GetId(), static.HostPrefix+"_") {
		badFields["id"] = "Invalid formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid arguments provided.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateHostRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetHostCatalogId(), static.HostCatalogPrefix+"_") {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	item := req.GetItem()
	if item == nil {
		return handlers.InvalidArgumentErrorf("Invalid arguments provided.", map[string]string{"item": "this field is required."})
	}
	switch host.SubtypeFromId(req.GetHostCatalogId()) {
	case host.StaticSubtype:
		if item.GetType() != "" && item.GetType() != host.StaticSubtype.String() {
			badFields["type"] = "Doesn't match the parent resource's type."
		}
		attrs := &pb.StaticHostAttributes{}
		if err := handlers.StructToProto(item.GetAttributes(), attrs); err != nil {
			badFields["attributes"] = "Attribute fields do not match the expected format."
		}
		if attrs.GetAddress() == nil {
			badFields["attributes.address"] = "This is a required field for this type."
		}
	}
	if item.GetId() != "" {
		badFields["id"] = "This field is read only."
	}
	if item.GetHostCatalogId() != "" {
		badFields["host_catalog_id"] = "This field is read only."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This field is read only."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This field is read only."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid arguments provided.", badFields)
	}
	return nil
}

func validateUpdateRequest(req *pbs.UpdateHostRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), static.HostPrefix+"_") {
		badFields["id"] = "The field is incorrectly formatted."
	}
	if !validId(req.GetHostCatalogId(), static.HostCatalogPrefix+"_") {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}

	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "This field is required."
	}

	item := req.GetItem()
	if item == nil {
		// It is legitimate for no item to be specified in an update request as it indicates all fields provided in
		// the mask will be marked as unset.
		return nil
	}
	if item.GetVersion() == 0 {
		badFields["version"] = "Existing resource version is required for an update."
	}
	if item.GetType() != "" {
		badFields["type"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetHostCatalogId() != "" {
		badFields["host_catalog_id"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetId() != "" {
		badFields["id"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetCreatedTime() != nil {
		badFields["created_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if item.GetUpdatedTime() != nil {
		badFields["updated_time"] = "This is a read only field and cannot be specified in an update request."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}

	return nil
}

func validateListRequest(req *pbs.ListHostsRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetHostCatalogId(), static.HostCatalogPrefix+"_") {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateDeleteRequest(req *pbs.DeleteHostRequest) error {
	badFields := map[string]string{}
	if !validId(req.GetHostCatalogId(), static.HostCatalogPrefix+"_") {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if !validId(req.GetId(), static.HostPrefix+"_") {
		badFields["id"] = "The field is incorrectly formatted."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid arguments provided.", badFields)
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
