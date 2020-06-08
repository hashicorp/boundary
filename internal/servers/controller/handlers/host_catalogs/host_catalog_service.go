package host_catalogs

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/host/static"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const (
	orgIdFieldName     = "org_id"
	projectIdFieldName = "project_id"
)

type catalogType int

const (
	unknownType catalogType = iota
	staticType
)

func (t catalogType) String() string {
	switch t {
	case staticType:
		return "Static"
	}
	return "Unknown"
}

func (t catalogType) idPrefix() string {
	switch t {
	case staticType:
		return static.HostCatalogPrefix + "_"
	}
	return "unknown"
}

func typeFromTypeField(t string) catalogType {
	switch {
	case strings.EqualFold(strings.TrimSpace(t), staticType.String()):
		return staticType
	}
	return unknownType
}

func typeFromId(id string) catalogType {
	switch {
	case strings.HasPrefix(id, staticType.idPrefix()):
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
	staticRepoFn func() (*static.Repository, error)
}

var _ pbs.HostCatalogServiceServer = Service{}

// NewService returns a host catalog Service which handles host catalog related requests to watchtower and uses the provided
// repositories for storage and retrieval.
func NewService(repoFn func() (*static.Repository, error)) (Service, error) {
	if repoFn == nil {
		return Service{}, fmt.Errorf("nil static repository provided")
	}
	return Service{staticRepoFn: repoFn}, nil
}

func (s Service) ListHostCatalogs(ctx context.Context, req *pbs.ListHostCatalogsRequest) (*pbs.ListHostCatalogsResponse, error) {
	return nil, status.Error(codes.Unimplemented, "Requested method is unimplemented for Host Catalogs.")
}

// GetHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) GetHostCatalog(ctx context.Context, req *pbs.GetHostCatalogRequest) (*pbs.GetHostCatalogResponse, error) {
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
	return &pbs.GetHostCatalogResponse{Item: hc}, nil
}

// CreateHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) CreateHostCatalog(ctx context.Context, req *pbs.CreateHostCatalogRequest) (*pbs.CreateHostCatalogResponse, error) {
	if err := validateCreateRequest(req); err != nil {
		return nil, err
	}
	hc, err := s.createInRepo(ctx, req.GetProjectId(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.CreateHostCatalogResponse{
		Item: hc,
		Uri:  fmt.Sprintf("orgs/%s/projects/%s/host-catalogs/%s", req.GetOrgId(), req.GetProjectId(), hc.GetId()),
	}, nil
}

// UpdateHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) UpdateHostCatalog(ctx context.Context, req *pbs.UpdateHostCatalogRequest) (*pbs.UpdateHostCatalogResponse, error) {
	ct := typeFromId(req.GetId())
	if ct == unknownType {
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"id": "Improperly formatted identifier used."})
	}
	if err := validateUpdateRequest(req, ct); err != nil {
		return nil, err
	}
	hc, err := s.updateInRepo(ctx, req.GetProjectId(), req.GetId(), req.GetUpdateMask().GetPaths(), req.GetItem())
	if err != nil {
		return nil, err
	}
	return &pbs.UpdateHostCatalogResponse{Item: hc}, nil
}

// DeleteHostCatalog implements the interface pbs.HostCatalogServiceServer.
func (s Service) DeleteHostCatalog(ctx context.Context, req *pbs.DeleteHostCatalogRequest) (*pbs.DeleteHostCatalogResponse, error) {
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
	h, err := static.NewHostCatalog(projId, opts...)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "Unable to build host catalog for update: %v.", err)
	}
	h.PublicId = id
	dbMask, err := toDbUpdateMask(mask)
	if err != nil {
		return nil, err
	}
	repo, err := s.staticRepoFn()
	if err != nil {
		return nil, err
	}
	out, rowsUpdated, err := repo.UpdateCatalog(ctx, h, dbMask)
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

// toDbUpdateMask converts the wire format's FieldMask into a list of strings containing FieldMask paths used
func toDbUpdateMask(paths []string) ([]string, error) {
	var dbPaths []string
	var invalid []string
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
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"update_mask": fmt.Sprintf("Invalid paths provided: %q", invalid)})
	}
	if len(dbPaths) == 0 {
		return nil, handlers.InvalidArgumentErrorf("Invalid argument provided.", map[string]string{"update_mask": "No valid paths provided."})
	}
	return dbPaths, nil
}

func toProto(in *static.HostCatalog) *pb.HostCatalog {
	out := pb.HostCatalog{
		Id:          in.GetPublicId(),
		Type:        &wrapperspb.StringValue{Value: staticType.String()},
		CreatedTime: in.GetCreateTime().GetTimestamp(),
		UpdatedTime: in.GetUpdateTime().GetTimestamp(),
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
func validateGetRequest(req *pbs.GetHostCatalogRequest, ct catalogType) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), ct.idPrefix()) {
		badFields["id"] = "Invalid formatted identifier."
	}
	if len(badFields) > 0 {
		return handlers.InvalidArgumentErrorf("Invalid arguments provided.", badFields)
	}
	return nil
}

func validateCreateRequest(req *pbs.CreateHostCatalogRequest) error {
	badFields := validateAncestors(req)
	item := req.GetItem()
	if item == nil {
		badFields["item"] = "This field is required."
	}
	if item.GetType() == nil {
		badFields["type"] = "This field is required."
	}
	if typeFromTypeField(item.GetType().GetValue()) == unknownType {
		badFields["type"] = "Provided type is unknown."
	}
	if item.GetId() != "" {
		badFields["id"] = "This field is read only."
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

func validateUpdateRequest(req *pbs.UpdateHostCatalogRequest, ct catalogType) error {
	badFields := validateAncestors(req)
	if !validId(req.GetId(), ct.idPrefix()) {
		badFields["id"] = "The field is incorrectly formatted."
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
	if item.GetType() != nil {
		badFields["type"] = "This is a read only field and cannot be specified in an update request."
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

func validateDeleteRequest(req *pbs.DeleteHostCatalogRequest, ct catalogType) error {
	badFields := validateAncestors(req)
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

type ancestorProvider interface {
	GetOrgId() string
	GetProjectId() string
}

// validateAncestors verifies that the ancestors of this call are set and formatted correctly.
func validateAncestors(r ancestorProvider) map[string]string {
	badFields := make(map[string]string)
	if r.GetOrgId() == "" {
		badFields[orgIdFieldName] = "The field is missing but required."
	}
	if r.GetProjectId() == "" {
		badFields[projectIdFieldName] = "The field is missing but required."
	}
	if len(badFields) > 0 {
		return badFields
	}

	if !validId(r.GetOrgId(), "o_") {
		badFields[orgIdFieldName] = "The field is incorrectly formatted."
	}
	if !validId(r.GetProjectId(), "p_") {
		badFields[projectIdFieldName] = "The field is incorrectly formatted."
	}
	return badFields
}
