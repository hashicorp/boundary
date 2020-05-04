package host_catalogs_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	"github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/repo"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_catalogs"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeRepo struct {
	lookupParam string
	listParam   string
	deleteParam string
	createParam string
	updateParam string

	lookup func() (*repo.HostCatalog, error)
	list   func() ([]repo.HostCatalog, error)
	delete func() (bool, error)
	create func() (*repo.HostCatalog, error)
	update func() (*repo.HostCatalog, error)
}

func (f *fakeRepo) LookupHostCatalog(ctx context.Context, id string) (*repo.HostCatalog, error) {
	f.lookupParam = id
	if f.lookup == nil {
		panic("Unexpected call to LookupHostCatalog")
	}
	return f.lookup()
}

func (f *fakeRepo) ListHostCatalogs(ctx context.Context, scopeID string) ([]repo.HostCatalog, error) {
	f.listParam = scopeID
	if f.list == nil {
		panic("Unexpected call to ListHostCatalogs")
	}
	return f.list()
}

func (f *fakeRepo) DeleteHostCatalog(ctx context.Context, id string) (bool, error) {
	f.deleteParam = id
	if f.delete == nil {
		panic("Unexpected call to DeleteHostCatalog")
	}
	return f.delete()
}

func (f *fakeRepo) CreateHostCatalog(ctx context.Context, scopeID, id string, hc repo.HostCatalog) (*repo.HostCatalog, error) {
	f.createParam = id
	if f.create == nil {
		panic("Unexpected call to CreateHostCatalog")
	}
	return f.create()
}

func (f *fakeRepo) UpdateHostCatalog(ctx context.Context, scopeID, id string, hc repo.HostCatalog, masks string) (*repo.HostCatalog, error) {
	f.updateParam = scopeID
	if f.update == nil {
		panic("Unexpected call to UpdateHostCatalog")
	}
	return f.update()
}

func TestDelete(t *testing.T) {
	toMerge := &services.DeleteHostCatalogRequest{
		OrgId:     "1",
		ProjectId: "2",
		Id:        "3",
	}

	repoReturns := func(b bool, err error) func() (bool, error) {
		return func() (bool, error) { return b, err }
	}

	cases := []struct {
		name     string
		repoResp func() (bool, error)
		req      *services.DeleteHostCatalogRequest
		res      *services.DeleteHostCatalogResponse
		errCode  codes.Code
	}{
		{
			name:     "Delete Existing record",
			repoResp: repoReturns(true, nil),
			req:      &services.DeleteHostCatalogRequest{Id: "exists"},
			res:      &services.DeleteHostCatalogResponse{Existed: true},
			errCode:  codes.OK,
		},
		{
			name:     "Delete always succeeds even for non existant catalogs",
			repoResp: repoReturns(false, nil),
			req:      &services.DeleteHostCatalogRequest{Id: "This doesn't exist."},
			res:      &services.DeleteHostCatalogResponse{},
			errCode:  codes.OK,
		},
		{
			name:     "Repo Errors passed on to client",
			repoResp: repoReturns(false, fmt.Errorf("Some Failure")),
			req:      &services.DeleteHostCatalogRequest{Id: "exists"},
			res:      nil,
			errCode:  codes.Internal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*services.DeleteHostCatalogRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{delete: tc.repoResp}
			s := host_catalogs.NewService(repo)

			got, gErr := s.DeleteHostCatalog(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("DeleteHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
			}

			if got, want := repo.deleteParam, tc.req.Id; got != want {
				t.Errorf("DeleteHostCatalog(%+v) results in %q passed to repo, wanted %q", req, got, want)
			}
		})
	}
}

func TestGet(t *testing.T) {
	var err error
	toMerge := &services.GetHostCatalogRequest{
		OrgId:     "1",
		ProjectId: "2",
		Id:        "requested id",
	}

	rHostCatalog := &repo.HostCatalog{
		ID:           "requested id",
		FriendlyName: "friendlyname",
		ScopeID:      "scopeid",
		CreatedTime:  time.Now(),
		UpdatedTime:  time.Now(),
	}

	pHostCatalog := &hosts.HostCatalog{
		FriendlyName: &wrappers.StringValue{Value: rHostCatalog.FriendlyName},
	}
	if pHostCatalog.CreatedTime, err = ptypes.TimestampProto(rHostCatalog.CreatedTime); err != nil {
		t.Fatalf("Failed to parse CreatedTime timestamp: %v", err)
	}
	if pHostCatalog.UpdatedTime, err = ptypes.TimestampProto(rHostCatalog.UpdatedTime); err != nil {
		t.Fatalf("Failed to parse CreatedTime timestamp: %v", err)
	}

	repoReturns := func(h *repo.HostCatalog, err error) func() (*repo.HostCatalog, error) {
		return func() (*repo.HostCatalog, error) { return h, err }
	}

	cases := []struct {
		name     string
		repoResp func() (*repo.HostCatalog, error)
		req      *services.GetHostCatalogRequest
		res      *services.GetHostCatalogResponse
		errCode  codes.Code
	}{
		{
			name:     "Get an Existing HostCatalog",
			repoResp: repoReturns(rHostCatalog, nil),
			req:      &services.GetHostCatalogRequest{Id: "exists"},
			res:      &services.GetHostCatalogResponse{Item: pHostCatalog},
			errCode:  codes.OK,
		},
		{
			name:     "Get a non existant Host Catalog",
			repoResp: repoReturns(nil, nil),
			req:      &services.GetHostCatalogRequest{Id: "doesnt exist"},
			res:      nil,
			errCode:  codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*services.GetHostCatalogRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{lookup: tc.repoResp}
			s := host_catalogs.NewService(repo)

			got, gErr := s.GetHostCatalog(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("GetHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("GetHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
			}

			if got, want := repo.lookupParam, tc.req.Id; got != want {
				t.Errorf("GetHostCatalog(%+v) results in %q passed to repo, wanted %q", req, got, want)
			}
		})
	}
}
