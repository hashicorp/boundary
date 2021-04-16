package host_sets

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/errors"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hostsets"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/perms"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/sdk/strutil"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager

	// IdActions contains the set of actions that can be performed on
	// individual resources
	IdActions = action.ActionSet{
		action.NoOp,
		action.Read,
		action.Update,
		action.Delete,
		action.AddHosts,
		action.SetHosts,
		action.RemoveHosts,
	}

	// CollectionActions contains the set of actions that can be performed on
	// this collection
	CollectionActions = action.ActionSet{
		action.Create,
		action.List,
	}
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.HostSet{}, &pb.HostSet{}); err != nil {
		panic(err)
	}
}

type Service struct {
	pbs.UnimplementedHostSetServiceServer

	staticRepoFn common.StaticRepoFactory
}

var _ pbs.HostSetServiceServer = Service{}

// NewService returns a host set Service which handles host set related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn common.StaticRepoFactory) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil static repository provided")
	}
	return Service{staticRepoFn: repoFn}, nil
}

func (s Service) ListHostSets(ctx context.Context, req *pbs.ListHostSetsRequest) (*pbs.ListHostSetsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetHostCatalogId(), action.List)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hl, err := s.listFromRepo(ctx, req.GetHostCatalogId(), authResults.UserId == auth.AnonymousUserId)
	if err != nil {
		return nil, err
	}
	filter, err := handlers.NewFilter(req.GetFilter())
	if err != nil {
		return nil, err
	}
	finalItems := make([]*pb.HostSet, 0, len(hl))
	res := &perms.Resource{
		ScopeId: authResults.Scope.Id,
		Type:    resource.HostSet,
		Pin:     req.GetHostCatalogId(),
	}
	for _, item := range hl {
		item.Scope = authResults.Scope
		item.AuthorizedActions = authResults.FetchActionSetForId(ctx, item.Id, IdActions, auth.WithResource(res)).Strings()
		if len(item.AuthorizedActions) == 0 {
			continue
		}
		if filter.Match(item) {
			finalItems = append(finalItems, item)
		}
	}
	return &pbs.ListHostSetsResponse{Items: finalItems}, nil
}

// GetHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) GetHostSet(ctx context.Context, req *pbs.GetHostSetRequest) (*pbs.GetHostSetResponse, error) {
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
	hc.AuthorizedActions = authResults.FetchActionSetForId(ctx, hc.Id, IdActions).Strings()
	return &pbs.GetHostSetResponse{Item: hc}, nil
}

// CreateHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) CreateHostSet(ctx context.Context, req *pbs.CreateHostSetRequest) (*pbs.CreateHostSetResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	cat, authResults := s.parentAndAuthResult(ctx, req.GetItem().GetHostCatalogId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	h, err := s.createInRepo(ctx, authResults.Scope.GetId(), cat.GetPublicId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	h.Scope = authResults.Scope
	h.AuthorizedActions = authResults.FetchActionSetForId(ctx, h.Id, IdActions).Strings()
	return &pbs.CreateHostSetResponse{
		Item: h,
		Uri:  fmt.Sprintf("host-sets/%s", h.GetId()),
	}, nil
}

// UpdateHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) UpdateHostSet(ctx context.Context, req *pbs.UpdateHostSetRequest) (*pbs.UpdateHostSetResponse, error) {
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
	hc.AuthorizedActions = authResults.FetchActionSetForId(ctx, hc.Id, IdActions).Strings()
	return &pbs.UpdateHostSetResponse{Item: hc}, nil
}

// DeleteHostSet implements the interface pbs.HostSetServiceServer.
func (s Service) DeleteHostSet(ctx context.Context, req *pbs.DeleteHostSetRequest) (*pbs.DeleteHostSetResponse, error) {
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
	return &pbs.DeleteHostSetResponse{}, nil
}

// AddHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) AddHostSetHosts(ctx context.Context, req *pbs.AddHostSetHostsRequest) (*pbs.AddHostSetHostsResponse, error) {
	if err := validateAddRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.AddHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, err := s.addInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	g.Scope = authResults.Scope
	g.AuthorizedActions = authResults.FetchActionSetForId(ctx, g.Id, IdActions).Strings()
	return &pbs.AddHostSetHostsResponse{Item: g}, nil
}

// SetHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) SetHostSetHosts(ctx context.Context, req *pbs.SetHostSetHostsRequest) (*pbs.SetHostSetHostsResponse, error) {
	if err := validateSetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.SetHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, err := s.setInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	g.Scope = authResults.Scope
	g.AuthorizedActions = authResults.FetchActionSetForId(ctx, g.Id, IdActions).Strings()
	return &pbs.SetHostSetHostsResponse{Item: g}, nil
}

// RemoveHostSetHosts implements the interface pbs.HostSetServiceServer.
func (s Service) RemoveHostSetHosts(ctx context.Context, req *pbs.RemoveHostSetHostsRequest) (*pbs.RemoveHostSetHostsResponse, error) {
	if err := validateRemoveRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.parentAndAuthResult(ctx, req.GetId(), action.RemoveHostSets)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	g, err := s.removeInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetHostIds(), req.GetVersion())
	if err != nil {
		return nil, err
	}
	g.Scope = authResults.Scope
	g.AuthorizedActions = authResults.FetchActionSetForId(ctx, g.Id, IdActions).Strings()
	return &pbs.RemoveHostSetHostsResponse{Item: g}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	h, m, err := repo.LookupSet(ctx, id)
	if err != nil {
		return nil, err
	}
	if h == nil {
		return nil, handlers.NotFoundErrorf("Host Set %q doesn't exist.", id)
	}
	return toProto(h, m), nil
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
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build host set for creation: %v.", err)
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateSet(ctx, scopeId, h)
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, fmt.Errorf("unable to create host set: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to create host set but no error returned from repository.")
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
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to build host set for update: %v.", err)
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
	out, m, rowsUpdated, err := repo.UpdateSet(ctx, scopeId, h, item.GetVersion(), dbMask)
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, fmt.Errorf("unable to update host set: %w.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Host Set %q doesn't exist or incorrect version provided.", id)
	}
	return toProto(out, m), nil
}

func (s Service) deleteFromRepo(ctx context.Context, scopeId, id string) (bool, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteSet(ctx, scopeId, id)
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return false, e
		}
		return false, fmt.Errorf("unable to delete host: %w", err)
	}
	return rows > 0, nil
}

func (s Service) listFromRepo(ctx context.Context, catalogId string, anonUser bool) ([]*pb.HostSet, error) {
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
		outH = append(outH, toProto(h, nil, handlers.WithAnonymousListing(anonUser)))
	}
	return outH, nil
}

func (s Service) addInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.AddSetMembers(ctx, scopeId, setId, version, strutil.RemoveDuplicates(hostIds, false))
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to add hosts to host set: %v.", err)
	}
	out, m, err := repo.LookupSet(ctx, setId)
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, fmt.Errorf("unable to look up host set after adding hosts: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup host set after adding hosts to it.")
	}
	return toProto(out, m), nil
}

func (s Service) setInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	_, _, err = repo.SetSetMembers(ctx, scopeId, setId, version, strutil.RemoveDuplicates(hostIds, false))
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to set hosts in host set: %v.", err)
	}

	out, m, err := repo.LookupSet(ctx, setId)
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, fmt.Errorf("unable to look up host set after setting hosts: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup host set after setting hosts for it.")
	}
	return toProto(out, m), nil
}

func (s Service) removeInRepo(ctx context.Context, scopeId, setId string, hostIds []string, version uint32) (*pb.HostSet, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	_, err = repo.DeleteSetMembers(ctx, scopeId, setId, version, strutil.RemoveDuplicates(hostIds, false))
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to remove hosts from host set: %v.", err)
	}
	out, m, err := repo.LookupSet(ctx, setId)
	if err != nil {
		if e := errors.Convert(err); e != nil {
			// This is a domain error, push this error through so the error interceptor can interpret it correctly.
			return nil, e
		}
		return nil, fmt.Errorf("unable to look up host set: %w", err)
	}
	if out == nil {
		return nil, handlers.ApiErrorWithCodeAndMessage(codes.Internal, "Unable to lookup host set after removing hosts from it.")
	}
	return toProto(out, m), nil
}

func (s Service) parentAndAuthResult(ctx context.Context, id string, a action.Type) (*static.HostCatalog, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.staticRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var parentId string
	opts := []auth.Option{auth.WithType(resource.HostSet), auth.WithAction(a)}
	switch a {
	case action.List, action.Create:
		parentId = id
	default:
		set, _, err := repo.LookupSet(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if set == nil {
			res.Error = handlers.NotFoundError()
			return nil, res
		}
		parentId = set.GetCatalogId()
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

func toProto(in *static.HostSet, hs []*static.Host, opt ...handlers.Option) *pb.HostSet {
	anonListing := handlers.GetOpts(opt...).WithAnonymousListing
	out := pb.HostSet{
		Id:            in.GetPublicId(),
		HostCatalogId: in.GetCatalogId(),
		Type:          host.StaticSubtype.String(),
	}
	if in.GetDescription() != "" {
		out.Description = wrapperspb.String(in.GetDescription())
	}
	if in.GetName() != "" {
		out.Name = wrapperspb.String(in.GetName())
	}
	if !anonListing {
		out.CreatedTime = in.GetCreateTime().GetTimestamp()
		out.UpdatedTime = in.GetUpdateTime().GetTimestamp()
		out.Version = in.Version
		for _, h := range hs {
			out.HostIds = append(out.HostIds, h.GetPublicId())
		}
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
	return handlers.ValidateGetRequest(handlers.NoopValidatorFn, req, static.HostSetPrefix)
}

func validateCreateRequest(req *pbs.CreateHostSetRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if !handlers.ValidId(handlers.Id(req.GetItem().GetHostCatalogId()), static.HostCatalogPrefix) {
			badFields["host_catalog_id"] = "The field is incorrectly formatted."
		}
		switch host.SubtypeFromId(req.GetItem().GetHostCatalogId()) {
		case host.StaticSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != host.StaticSubtype.String() {
				badFields["type"] = "Doesn't match the parent resource's type."
			}
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostSetRequest) error {
	return handlers.ValidateUpdateRequest(req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch host.SubtypeFromId(req.GetId()) {
		case host.StaticSubtype:
			if req.GetItem().GetType() != "" && req.GetItem().GetType() != host.StaticSubtype.String() {
				badFields["type"] = "Cannot modify the resource type."
			}
		}
		return badFields
	}, static.HostSetPrefix)
}

func validateDeleteRequest(req *pbs.DeleteHostSetRequest) error {
	return handlers.ValidateDeleteRequest(handlers.NoopValidatorFn, req, static.HostSetPrefix)
}

func validateListRequest(req *pbs.ListHostSetsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetHostCatalogId()), static.HostCatalogPrefix) {
		badFields["host_catalog_id"] = "The field is incorrectly formatted."
	}
	if _, err := handlers.NewFilter(req.GetFilter()); err != nil {
		badFields["filter"] = fmt.Sprintf("This field could not be parsed. %v", err)
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}

func validateAddRequest(req *pbs.AddHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), static.HostSetPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields["host_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostPrefix) {
			badFields["host_ids"] = "Incorrectly formatted host identifier."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateSetRequest(req *pbs.SetHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), static.HostSetPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostPrefix) {
			badFields["host_ids"] = "Incorrectly formatted host identifier."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}

func validateRemoveRequest(req *pbs.RemoveHostSetHostsRequest) error {
	badFields := map[string]string{}
	if !handlers.ValidId(handlers.Id(req.GetId()), static.HostSetPrefix) {
		badFields["id"] = "Incorrectly formatted identifier."
	}
	if req.GetVersion() == 0 {
		badFields["version"] = "Required field."
	}
	if len(req.GetHostIds()) == 0 {
		badFields["host_ids"] = "Must be non-empty."
	}
	for _, id := range req.GetHostIds() {
		if !handlers.ValidId(handlers.Id(id), static.HostPrefix) {
			badFields["host_ids"] = "Incorrectly formatted host identifier."
			break
		}
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Errors in provided fields.", badFields)
	}
	return nil
}
