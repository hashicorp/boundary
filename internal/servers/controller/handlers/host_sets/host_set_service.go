package host_sets

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type setType int

const (
	unknownType setType = iota
	staticType
)

func (t setType) String() string {
	switch t {
	case staticType:
		return "static"
	}
	return "unknown"
}

func (t setType) idPrefix() string {
	switch t {
	case staticType:
		return static.HostSetPrefix + "_"
	}
	return "unknown"
}

func typeFromTypeField(t string) setType {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), staticType.String()):
		return staticType
	}
	return unknownType
}

func typeFromId(id string) setType {
	switch {
	case strings.HasPrefix(id, staticType.idPrefix()):
		return staticType
	}
	return unknownType
}

var (
	maskManager handlers.MaskManager
	reInvalidID = regexp.MustCompile("[^A-Za-z0-9]")
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&pb.HostSet{}, &store.HostSet{}); err != nil {
		panic(err)
	}
}

type Service struct {
	staticRepoFn common.StaticRepoFactory
}

var _ pbs.HostSetServiceServer = Service{}

// NewService returns a host catalog Service which handles host catalog related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn common.StaticRepoFactory) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil static repository provided")
	}
	return Service{staticRepoFn: repoFn}, nil
}

func (s Service) ListHostSets(ctx context.Context, req *pbs.ListHostSetsRequest) (*pbs.ListHostSetsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Requested method is unimplemented for Host Sets.")
}

// GetHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) GetHostSet(ctx context.Context, req *pbs.GetHostSetRequest) (*pbs.GetHostSetResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	ct := typeFromId(req.GetId())
	if ct == unknownType {
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"id": "Improperly formatted identifier used."})
	}
	if err := validateGetRequest(req, ct); err != nil {
		return nil, err
	}
	hc, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.GetHostSetResponse{Item: hc}, nil
}

// CreateHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) CreateHostSet(ctx context.Context, req *pbs.CreateHostSetRequest) (*pbs.CreateHostSetResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	h, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	h.Scope = authResults.Scope
	return &pbs.CreateHostSetResponse{
		Item: h,
		Uri:  fmt.Sprintf("scopes/%s/host-catalogs/%s/host-sets/%s", authResults.Scope.GetId(), req.GetHostCatalogId(), h.GetId()),
	}, nil
}

// UpdateHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) UpdateHostSet(ctx context.Context, req *pbs.UpdateHostSetRequest) (*pbs.UpdateHostSetResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	ct := typeFromId(req.GetId())
	if ct == unknownType {
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"id": "Improperly formatted identifier used."})
	}
	if err := validateUpdateRequest(req, ct); err != nil {
		return nil, err
	}
	hc, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetVersion(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.UpdateHostSetResponse{Item: hc}, nil
}

// DeleteHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) DeleteHostSet(ctx context.Context, req *pbs.DeleteHostSetRequest) (*pbs.DeleteHostSetResponse, error) {
	authResults := auth.Verify(ctx)
	if !authResults.Valid {
		return nil, handlers.ForbiddenError()
	}
	ct := typeFromId(req.GetId())
	if ct == unknownType {
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"id": "Improperly formatted identifier used."})
	}
	if err := validateDeleteRequest(req, ct); err != nil {
		return nil, err
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteHostSetResponse{Existed: existed}, nil
}

// AddHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) AddHostSetHosts(ctx context.Context, request *pbs.AddHostSetHostsRequest) (*pbs.AddHostSetHostsResponse, error) {
	panic("implement me")
}

// SetHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) SetHostSetHosts(ctx context.Context, request *pbs.SetHostSetHostsRequest) (*pbs.SetHostSetHostsResponse, error) {
	panic("implement me")
}

// RemoveHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) RemoveHostSetHosts(ctx context.Context, request *pbs.RemoveHostSetHostsRequest) (*pbs.RemoveHostSetHostsResponse, error) {
	panic("implement me")
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	// h, err := repo.LookupSet(ctx, id)
	// if err != nil {
	// 	return nil, err
	// }
	_ = repo
	var h *static.HostSet
	if h == nil {
		return nil, handlers.NotFoundErrorf("Host set %q doesn't exist.", id)
	}
	return toProto(h), nil
}

func (s Service) createInRepo(ctx context.Context, projId string, item *pb.HostSet) (*pb.HostSet, error) {
	var opts []static.Option
	if item.GetName() != nil {
		opts = append(opts, static.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, static.WithDescription(item.GetDescription().GetValue()))
	}
	h, err := static.NewHostSet(projId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host set for creation: %v.", err)
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	// out, err := repo.CreateSet(ctx, h)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, "Unable to create host set: %v.", err)
	// }
	_ = repo
	out := h
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create host set but no error returned from repository.")
	}
	return toProto(out), nil
}

func (s Service) updateInRepo(ctx context.Context, projId, id string, version uint32, mask []string, item *pb.HostSet) (*pb.HostSet, error) {
	var opts []static.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, static.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, static.WithName(name.GetValue()))
	}
	h, err := static.NewHostSet(projId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host set for update: %v.", err)
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
	// out, rowsUpdated, err := repo.UpdateSet(ctx, h, version, dbMask)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, "Unable to update host set: %v.", err)
	// }
	// if rowsUpdated == 0 {
	// 	return nil, handlers.NotFoundErrorf("Host set %q doesn't exist.", id)
	// }
	_ = repo
	out := h
	return toProto(out), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return false, err
	}
	// rows, err := repo.DeleteSet(ctx, id)
	// if err != nil {
	// 	return false, status.Errorf(codes.Internal, "Unable to delete host: %v.", err)
	// }
	_ = repo
	rows := 0
	return rows > 0, nil
}

func toProto(in *static.HostSet) *pb.HostSet {
	out := pb.HostSet{
		Id:          in.GetPublicId(),
		Type:        staticType.String(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
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
//  * The type asserted by the ID and/or field is known
//  * If relevant, the type derived from the id prefix matches what is claimed by the type field
func validateGetRequest(req *pbs.GetHostSetRequest, ct setType) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), ct.idPrefix()) {
		badFields["id"] = "Invalid formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid arguments provided.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateHostSetRequest) error {
	badFields := map[string]string{}
	item := req.GetItem()
	if item == nil {
		badFields["item"] = "This field is required."
	}
	if item.GetType() == "" {
		badFields["type"] = "This field is required."
	}
	if typeFromTypeField(item.GetType()) == unknownType {
		badFields["type"] = "Provided type is unknown."
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

func validateUpdateRequest(req *pbs.UpdateHostSetRequest, ct setType) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), ct.idPrefix()) {
		badFields["id"] = "The field is incorrectly formatted."
	}
	if !validId(req.GetHostCatalogId(), static.HostCatalogPrefix+"_") {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}

	if req.GetUpdateMask() == nil {
		badFields["update_mask"] = "This field is required."
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

func validateDeleteRequest(req *pbs.DeleteHostSetRequest, ct setType) error {
	badFields := map[string]string{}
	if !validId(req.GetId(), ct.idPrefix()) {
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
