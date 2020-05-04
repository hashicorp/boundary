package host_sets_test

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/repo"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_sets"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeRepo struct {
	lookupParam string
	listParam   string
	deleteParam string
	createParam string
	updateParam string

	lookup func() (*repo.HostSet, error)
	list   func() ([]repo.HostSet, error)
	delete func() (bool, error)
	create func() (*repo.HostSet, error)
	update func() (*repo.HostSet, error)
}

func (f *fakeRepo) LookupHostSet(ctx context.Context, id string) (*repo.HostSet, error) {
	f.lookupParam = id
	if f.lookup == nil {
		panic("Unexpected call to LookupHostCatalog")
	}
	return f.lookup()
}

func (f *fakeRepo) ListHostSets(ctx context.Context, scopeID, catalogID string) ([]repo.HostSet, error) {
	f.listParam = scopeID
	if f.list == nil {
		panic("Unexpected call to ListHostCatalogs")
	}
	return f.list()
}

func (f *fakeRepo) DeleteHostSet(ctx context.Context, id string) (bool, error) {
	f.deleteParam = id
	if f.delete == nil {
		panic("Unexpected call to DeleteHostCatalog")
	}
	return f.delete()
}

func (f *fakeRepo) CreateHostSet(ctx context.Context, catalogID, id string, hc repo.HostSet) (*repo.HostSet, error) {
	f.createParam = id
	if f.create == nil {
		panic("Unexpected call to CreateHostCatalog")
	}
	return f.create()
}

func (f *fakeRepo) UpdateHostSet(ctx context.Context, scopeID, id string, hc repo.HostSet, masks string) (*repo.HostSet, error) {
	f.updateParam = scopeID
	if f.update == nil {
		panic("Unexpected call to UpdateHostCatalog")
	}
	return f.update()
}

func TestDelete(t *testing.T) {
	toMerge := &pbs.DeleteHostSetRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
		Id:            "4",
	}

	repoReturns := func(b bool, err error) func() (bool, error) {
		return func() (bool, error) { return b, err }
	}

	cases := []struct {
		name     string
		repoResp func() (bool, error)
		req      *pbs.DeleteHostSetRequest
		res      *pbs.DeleteHostSetResponse
		errCode  codes.Code
	}{
		{
			name:     "Delete succeeds for existing",
			repoResp: repoReturns(true, nil),
			req:      &pbs.DeleteHostSetRequest{Id: "exists"},
			res:      &pbs.DeleteHostSetResponse{Existed: true},
			errCode:  codes.OK,
		},
		{
			name:     "Delete succeeds even for non existing resources",
			repoResp: repoReturns(false, nil),
			req:      &pbs.DeleteHostSetRequest{Id: "this doesn't exist"},
			res:      &pbs.DeleteHostSetResponse{},
			errCode:  codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.DeleteHostSetRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{delete: tc.repoResp}
			s := host_sets.NewService(repo)

			got, gErr := s.DeleteHostSet(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("DeleteHostSet(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHostSet(%q) got response %q, wanted %q", req, got, tc.res)
			}

			if got, want := repo.deleteParam, req.Id; got != want {
				t.Errorf("DeleteHostSet(%+v) results in %q passed to repo, wanted %q", req, got, want)
			}
		})
	}
}
