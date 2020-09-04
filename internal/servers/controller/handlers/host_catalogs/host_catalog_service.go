package host_catalogs

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/auth"
	pb "github.com/hashicorp/boundary/internal/gen/controller/api/resources/hostcatalogs"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/host/static/store"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller/common"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

var (
	maskManager handlers.MaskManager
)

func init() {
	var err error
	if maskManager, err = handlers.NewMaskManager(&store.HostCatalog{}, &pb.HostCatalog{}); err != nil {
		panic(err)
	}
}

type Service struct {
	staticRepoFn common.StaticRepoFactory
	iamRepoFn    common.IamRepoFactory
}

var _ pbs.HostCatalogServiceServer = Service{}

// NewService returns a host catalog Service which handles host catalog related requests to boundary and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn common.StaticRepoFactory, iamRepoFn common.IamRepoFactory) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil static repository provided")
	}
	if iamRepoFn == nil {
		return Service{}, fmt.Errorf("nil iam repository provided")
	}
	return Service{staticRepoFn: repoFn, iamRepoFn: iamRepoFn}, nil
}

func (s Service) ListHostCatalogs(ctx context.Context, req *pbs.ListHostCatalogsRequest) (*pbs.ListHostCatalogsResponse, error) {
	if err := validateListRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetScopeId(), action.List)
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
	return &pbs.ListHostCatalogsResponse{Items: ul}, nil
}

// GetHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) GetHostCatalog(ctx context.Context, req *pbs.GetHostCatalogRequest) (*pbs.GetHostCatalogResponse, error) {
	if err := validateGetRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetId(), action.Read)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hc, err := s.getFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.GetHostCatalogResponse{Item: hc}, nil
}

// CreateHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) CreateHostCatalog(ctx context.Context, req *pbs.CreateHostCatalogRequest) (*pbs.CreateHostCatalogResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetItem().GetScopeId(), action.Create)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hc, err := s.createInRepo(ctx, authResults.Scope.GetId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.CreateHostCatalogResponse{
		Item: hc,
		Uri:  fmt.Sprintf("host-catalogs/%s", hc.GetId()),
	}, nil
}

// UpdateHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) UpdateHostCatalog(ctx context.Context, req *pbs.UpdateHostCatalogRequest) (*pbs.UpdateHostCatalogResponse, error) {
	if err := validateUpdateRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetId(), action.Update)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	hc, err := s.updateInRepo(ctx, authResults.Scope.GetId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	hc.Scope = authResults.Scope
	return &pbs.UpdateHostCatalogResponse{Item: hc}, nil
}

// DeleteHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) DeleteHostCatalog(ctx context.Context, req *pbs.DeleteHostCatalogRequest) (*pbs.DeleteHostCatalogResponse, error) {
	if err := validateDeleteRequest(req); err != nil {
		return nil, err
	}
	_, authResults := s.pinAndAuthResult(ctx, req.GetId(), action.Delete)
	if authResults.Error != nil {
		return nil, authResults.Error
	}
	existed, err := s.deleteFromRepo(ctx, req.GetId())
	if err != nil {
		return nil, err
	}
	return &pbs.DeleteHostCatalogResponse{Existed: existed}, nil
}

func (s Service) getFromRepo(ctx context.Context, id string) (*pb.HostCatalog, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	hc, err := repo.LookupCatalog(ctx, id)
	if err != nil {
		return nil, err
	}
	if hc == nil {
		return nil, handlers.NotFoundErrorf("Host catalog %q doesn't exist.", id)
	}
	return toProto(hc), nil
}

func (s Service) listFromRepo(ctx context.Context, scopeId string) ([]*pb.HostCatalog, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	ul, err := repo.ListCatalogs(ctx, scopeId)
	if err != nil {
		return nil, err
	}
	var outUl []*pb.HostCatalog
	for _, u := range ul {
		outUl = append(outUl, toProto(u))
	}
	return outUl, nil
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
		return nil, status.Errorf(codes.Internal, "Unable to build host catalog for creation: %v.", err)
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, err := repo.CreateCatalog(ctx, h)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to create host catalog: %v.", err)
	}
	if out == nil {
		return nil, status.Error(codes.Internal, "Unable to create host catalog but no error returned from repository.")
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
	version := item.GetVersion()
	h, err := static.NewHostCatalog(projId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host catalog for update: %v.", err)
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
	out, rowsUpdated, err := repo.UpdateCatalog(ctx, h, version, dbMask)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to update host catalog: %v.", err)
	}
	if rowsUpdated == 0 {
		return nil, handlers.NotFoundErrorf("Host catalog %q doesn't exist.", id)
	}
	return toProto(out), nil
}

func (s Service) deleteFromRepo(ctx context.Context, id string) (bool, error) {
	repo, err := s.staticRepoFn()
	if err != nil {
		return false, err
	}
	rows, err := repo.DeleteCatalog(ctx, id)
	if err != nil {
		return false, status.Errorf(codes.Internal, "Unable to delete host: %v.", err)
	}
	return rows > 0, nil
}

func (s Service) pinAndAuthResult(ctx context.Context, id string, a action.Type) (*iam.Scope, auth.VerifyResults) {
	res := auth.VerifyResults{}
	repo, err := s.staticRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}
	iamRepo, err := s.iamRepoFn()
	if err != nil {
		res.Error = err
		return nil, res
	}

	var scp *iam.Scope
	opts := []auth.Option{auth.WithType(resource.HostCatalog), auth.WithAction(a)}
	switch a {
	case action.List:
		fallthrough
	case action.Create:
		scp, err = iamRepo.LookupScope(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if scp == nil {
			res.Error = handlers.ForbiddenError()
			return nil, res
		}
		opts = append(opts, auth.WithScopeId(id))
	default:
		// If the action isn't one of the above ones, than it is an action on an individual resource and the
		// id provided is for the resource itself.
		cat, err := repo.LookupCatalog(ctx, id)
		if err != nil {
			res.Error = err
			return nil, res
		}
		if cat == nil {
			res.Error = handlers.ForbiddenError()
			return nil, res
		}

		scp, err = iamRepo.LookupScope(ctx, cat.GetScopeId())
		if err != nil {
			res.Error = err
			return nil, res
		}
		if scp == nil {
			res.Error = handlers.ForbiddenError()
			return nil, res
		}
		opts = append(opts, auth.WithId(id), auth.WithScopeId(scp.GetPublicId()))
	}
	authResults := auth.Verify(ctx, opts...)
	return scp, authResults
}

func toProto(in *static.HostCatalog) *pb.HostCatalog {
	out := pb.HostCatalog{
		Id:          in.GetPublicId(),
		ScopeId:     in.GetScopeId(),
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
		Version:     in.GetVersion(),
		Type:        host.StaticSubtype.String(),
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
func validateGetRequest(req *pbs.GetHostCatalogRequest) error {
	return handlers.ValidateGetRequest(static.HostCatalogPrefix, req, handlers.NoopValidatorFn)
}

func validateCreateRequest(req *pbs.CreateHostCatalogRequest) error {
	return handlers.ValidateCreateRequest(req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		switch host.SubtypeFromType(req.GetItem().GetType()) {
		case host.StaticSubtype:
		default:
			badFields["type"] = fmt.Sprintf("This is a required field and must be %q.", host.StaticSubtype.String())
		}
		return badFields
	})
}

func validateUpdateRequest(req *pbs.UpdateHostCatalogRequest) error {
	return handlers.ValidateUpdateRequest(static.HostCatalogPrefix, req, req.GetItem(), func() map[string]string {
		badFields := map[string]string{}
		if req.GetItem().GetType() != "" {
			badFields["type"] = "This is a read only field and cannot be specified in an update request."
		}
		return badFields
	})
}

func validateDeleteRequest(req *pbs.DeleteHostCatalogRequest) error {
	return handlers.ValidateDeleteRequest(static.HostCatalogPrefix, req, handlers.NoopValidatorFn)
}

func validateListRequest(req *pbs.ListHostCatalogsRequest) error {
	badFields := map[string]string{}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Improperly formatted identifier.", badFields)
	}
	return nil
}
