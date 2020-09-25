package hosts

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
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
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetHostCatalogId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
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
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
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
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetHostCatalogId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	h, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem().GetHostCatalogId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	h.Scope = authResults.Scope
	return &pbs.CreateHostResponse{
		Item: h,
		Uri:  fmt.Sprintf("hosts/%s", h.GetId()),
	}, nil
}

// UpdateHost implements the interface pbs.HostServiceServer.
func (s Service) UpdateHost(ctx context.Context, req *pbs.UpdateHostRequest) (*pbs.UpdateHostResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	cat, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hc, err := s.updateInRepo(ctx, authResults.Scope.GetId(), cat.GetPublicId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.UpdateHostResponse{Item: hc}, nil
}

// DeleteHost implements the interface pbs.HostServiceServer.
func (s Service) DeleteHost(ctx context.Context, req *pbs.DeleteHostRequest) (*pbs.DeleteHostResponse, error) {
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
	return &pbs.DeleteHostResponse{}, nil
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
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Failed converting attributes to subtype proto: %s", err)
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
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build host for creation: %v.", err)
	}

	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateHost(ctx, scopeId, h)
	if err != nil {
		if db.IsUniqueError(err) || errors.Is(err, db.ErrNotUnique) {
			// Push this error through so the error interceptor can interpret it correctly.
			return nil, err
		}
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host: %v.", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host but no error returned from repository.")
	}
	return toProto(out, nil)
}

func (s Service) updateInRepo(ctx context.Context, scopeId, catalogId, id string, mask []string, item *pb.Host) (*pb.Host, error) {
	ha := &pb.StaticHostAttributes{}
	if err := handlers.StructToProto(item.GetAttributes(), ha); err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Failed converting attributes to subtype proto: %s", err)
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
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build host for update: %v.", err)
	}
	h.PublicId = id
	dbMask := maskManager.Translate(mask)
	if len(dbMask) == 0 {
		return nil, handlers.InvalidArgumentErrorf("No valid fields included in the update mask.", map[string]string{"update_mask": "No valid fields provided in the update mask."})
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateHost(ctx, scopeId, h, item.GetVersion(), dbMask)
	if err != nil {
		return nil, fmt.Errorf("unable to update host: %w", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Host %q doesn't exist or incorrect version provided.", id)
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
		return false, fmt.Errorf("unable to delete host: %w", err)
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

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (*static.HostCatalog, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.staticRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.Host), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		h, err := repo.LookupHost(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if h == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		parentId = h.GetCatalogId()
		opts = append(opts, auth.WithId(id))
	}

	cat, err := repo.LookupCatalog(ctx, parentId)
	if err != nil {
		res.Error = err
		return nil, res
	}
	if cat == nil {
		res.Error = handlers.NotFoundError()
		return nil, res
	}
	opts = append(opts, auth.WithScopeId(cat.GetScopeId()), auth.WithPin(parentId))
	return cat, auth.Verify(ctx, opts...)
}

func toProto(in *static.Host, members []*static.HostSet) (*pb.Host, error) {
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
		out.HostSetIds = append(out.HostSetIds, m.GetPublicId())
	}
	st, err := handlers.ProtoToStruct(&pb.StaticHostAttributes{Address: wrapperspb.String(in.GetAddress())})
	if err != nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to convert static attribute to struct: %s", err)
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
	return handlers.ValidateGetRequest(static.HostPrefix, req, func() map[string]string {
		badFields := map[string]string{}
		ct := host.SubtypeFromId(req.GetId())
		if ct == host.UnknownSubtype {
			badFields["id"] = "Improperly formatted identifier used."
		}
		return badFields
	})
}

func validateCreateRequest(req *pbs.CreateHostRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(static.HostCatalogPrefix, req.GetItem().GetHostCatalogId()) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		switch host.SubtypeFromId(req.GetItem().GetHostCatalogId()) {
		case host.StaticSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != host.StaticSubtype.String() {
				badFields["type"] = "Doesn't match the parent resource's type."
			}
			attrs := &pb.StaticHostAttributes{}
			if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
				badFields["attributes"] = "Attribute fields do not match the expected format."
			}
			if attrs.GetAddress() == nil ||
				len(attrs.GetAddress().GetValue()) < static.MinHostAddressLength ||
				len(attrs.GetAddress().GetValue()) > static.MaxHostAddressLength {
				badFields["attributes.address"] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
			}
			_, _, err := net.SplitHostPort(attrs.GetAddress().GetValue())
			switch {
			case err == nil:
				badFields["attributes.address"] = "Address for static hosts does not support a port."
			case strings.Contains(err.Error(), "missing port in address"):
				// Bare hostname, which we want
			default:
				badFields["attributes.address"] = fmt.Sprintf("Error parsing address: %v.", err)
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostRequest) error {
	return handlers.ValidateUpdateRequest(static.HostPrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch host.SubtypeFromId(req.GetId()) {
		case host.StaticSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != host.StaticSubtype.String() {
				badFields["type"] = "Cannot modify the resource type."

				attrs := &pb.StaticHostAttributes{}
				if err := handlers.StructToProto(req.GetItem().GetAttributes(), attrs); err != nil {
					badFields["attributes"] = "Attribute fields do not match the expected format."
				}

				if handlers.MaskContains(req.GetUpdateMask().GetPaths(), "attributes.address") {
					if attrs.GetAddress() == nil ||
						len(strings.TrimSpace(attrs.GetAddress().GetValue())) < static.MinHostAddressLength ||
						len(strings.TrimSpace(attrs.GetAddress().GetValue())) > static.MaxHostAddressLength {
						badFields["attributes.address"] = fmt.Sprintf("Address length must be between %d and %d characters.", static.MinHostAddressLength, static.MaxHostAddressLength)
					}
				}
			}
		default:
			badFields["id"] = "Improperly formatted identifier used."
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteHostRequest) error {
	return handlers.ValidateDeleteRequest(static.HostPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(static.HostCatalogPrefix, req.GetHostCatalogId()) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
