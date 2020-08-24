package host_sets

import (
	"context"
	"fmt"

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
	return &pbs.ListHostSetsResponse{Items: hl}, nil
}

// GetHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) GetHostSet(ctx context.Context, req *pbs.GetHostSetRequest) (*pbs.GetHostSetResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateGetRequest(req); err != nil {
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
	return &pbs.CreateHostSetResponse{
		Item: h,
		Uri:  fmt.Sprintf("scopes/%s/host-catalogs/%s/host-sets/%s", authResults.Scope.GetId(), req.GetHostCatalogId(), h.GetId()),
	}, nil
}

// UpdateHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) UpdateHostSet(ctx context.Context, req *pbs.UpdateHostSetRequest) (*pbs.UpdateHostSetResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	hc, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetHostCatalogId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.UpdateHostSetResponse{Item: hc}, nil
}

// DeleteHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) DeleteHostSet(ctx context.Context, req *pbs.DeleteHostSetRequest) (*pbs.DeleteHostSetResponse, error) {
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
	return &pbs.DeleteHostSetResponse{Existed: existed}, nil
}

// AddHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) AddHostSetHosts(ctx context.Context, req *pbs.AddHostSetHostsRequest) (*pbs.AddHostSetHostsResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateAddRequest(req); err != nil {
		return nil, err
	}
	g, err := s.addInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	return &pbs.AddHostSetHostsResponse{Item: g}, nil
}

// SetHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) SetHostSetHosts(ctx context.Context, req *pbs.SetHostSetHostsRequest) (*pbs.SetHostSetHostsResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateSetRequest(req); err != nil {
		return nil, err
	}
	g, err := s.setInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	return &pbs.SetHostSetHostsResponse{Item: g}, nil
}

// RemoveHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) RemoveHostSetHosts(ctx context.Context, req *pbs.RemoveHostSetHostsRequest) (*pbs.RemoveHostSetHostsResponse, error) {
	authResults := auth.Verify(ctx)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	if err := validateRemoveRequest(req); err != nil {
		return nil, err
	}
	g, err := s.removeInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	return &pbs.RemoveHostSetHostsResponse{Item: g}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	h, err := repo.LookupSet(ctx, id)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, handlers.NotFoundErrorf("Host set %q doesn't exist.", id)
	}
	return toProto(h, nil), nil
}

func (s Service) createInRepo(ctx context.Context, scopeId, catalogId string, item *pb.HostSet) (*pb.HostSet, error) {
	var opts []static.Option
	if item.GetName() != nil {
		opts = append(opts, static.WithName(item.GetName().GetValue()))
	}
	if item.GetDescription() != nil {
		opts = append(opts, static.WithDescription(item.GetDescription().GetValue()))
	}
	h, err := static.NewHostSet(catalogId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host set for creation: %v.", err)
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateSet(ctx, scopeId, h)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create host set: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create host set but no error returned from repository.")
	}
	return toProto(out, nil), nil
}

func (s Service) updateInRepo(ctx context.Context, scopeId, catalogId, id string, mask []string, item *pb.HostSet) (*pb.HostSet, error) {
	var opts []static.Option
	if desc := item.GetDescription(); desc != nil {
		opts = append(opts, static.WithDescription(desc.GetValue()))
	}
	if name := item.GetName(); name != nil {
		opts = append(opts, static.WithName(name.GetValue()))
	}
	h, err := static.NewHostSet(catalogId, opts...)
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
	out, rowsUpdated, err := repo.UpdateSet(ctx, scopeId, h, item.GetVersion(), dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update host set: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Host set %q doesn't exist.", id)
	}
	return toProto(out, nil), nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteSet(ctx, scopeId, id)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete host: %v.", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, catalogId string) ([]*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	hl, err := repo.ListSets(ctx, catalogId)
	if err != nil {
		return nil, err
	}
	var outH []*pb.HostSet
	for _, h := range hl {
		outH = append(outH, toProto(h, nil))
	}
	return outH, nil
}

func (s Service) addInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	// _, err = repo.AddHostSetMembers(ctx, setId, version, hostIds)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, "Unable to add members to group: %v.", err)
	// }
	out, err := repo.LookupSet(ctx, setId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up group: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup group after adding member to it.")
	}
	return toProto(out, nil), nil
}

func (s Service) setInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	// _, _, err = repo.SetHostSetMembers(ctx, groupId, version, userIds)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, "Unable to set members on group: %v.", err)
	// }

	out, err := repo.LookupSet(ctx, setId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up group: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup group after setting members for it.")
	}
	return toProto(out, nil), nil
}

func (s Service) removeInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	// _, err = repo.RemoveHostSetMembers(ctx, hostSetId, version, userIds)
	// if err != nil {
	// 	return nil, status.Errorf(codes.Internal, "Unable to remove members from group: %v.", err)
	// }
	out, err := repo.LookupSet(ctx, setId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to look up group: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to lookup group after removing members from it.")
	}
	return toProto(out, nil), nil
}

func toProto(in *static.HostSet, members []*static.HostSetMember) *pb.HostSet {
	out := pb.HostSet{
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
		out.HostIds = append(out.HostIds, m.GetHostId())
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
func validateGetRequest(req *pbs.GetHostSetRequest) error {
	return handlers.ValidateGetRequest(static.HostSetPrefix, req, func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		return badFields
	})
}

func validateCreateRequest(req *pbs.CreateHostSetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}

		if req.GetItem().GetHostCatalogId() != "" {
			badFields["host_catalog_id"] = "This field is read only."
		}
		switch host.SubtypeFromId(req.GetHostCatalogId()) {
		case host.StaticSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != host.StaticSubtype.String() {
				badFields["type"] = "Doesn't match the parent resource's type."
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostSetRequest) error {
	return handlers.ValidateUpdateRequest(static.HostSetPrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		if req.GetItem().GetHostCatalogId() != "" {
			badFields["host_catalog_id"] = "This is a read only field and cannot be specified in an update request."
		}
		if req.GetItem().GetType() != "" {
			badFields["type"] = "This is a read only field and cannot be specified in an update request."
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteHostSetRequest) error {
	return handlers.ValidateDeleteRequest(static.HostSetPrefix, req, func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		return badFields
	})
}

func validateListRequest(req *pbs.ListHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRequest(req *pbs.AddHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if !handlers.ValidId(static.HostSetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields["host_ids"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRequest(req *pbs.SetHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if !handlers.ValidId(static.HostSetPrefix, req.GetId()) {
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

func validateRemoveRequest(req *pbs.RemoveHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if !handlers.ValidId(static.HostSetPrefix, req.GetId()) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields["host_ids"] = "Must be non-empty."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
