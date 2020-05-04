package hosts_test

import (
	"context"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/repo"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/hosts"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeRepo struct {
	lookupParam string
	listParam   string
	deleteParam string
	createParam string
	updateParam string

	lookup func() (*repo.Host, error)
	list   func() ([]repo.Host, error)
	delete func() (bool, error)
	create func() (*repo.Host, error)
	update func() (*repo.Host, error)
}

func (f *fakeRepo) LookupHost(ctx context.Context, id string) (*repo.Host, error) {
	f.lookupParam = id
	if f.lookup == nil {
		panic("Unexpected call to LookupHostCatalog")
	}
	return f.lookup()
}

func (f *fakeRepo) ListHosts(ctx context.Context, catalogID string) ([]repo.Host, error) {
	f.listParam = catalogID
	if f.list == nil {
		panic("Unexpected call to ListHostCatalogs")
	}
	return f.list()
}

func (f *fakeRepo) DeleteHost(ctx context.Context, id string) (bool, error) {
	f.deleteParam = id
	if f.delete == nil {
		panic("Unexpected call to DeleteHostCatalog")
	}
	return f.delete()
}

func (f *fakeRepo) CreateHost(ctx context.Context, catalogID, id string, hc repo.Host) (*repo.Host, error) {
	f.createParam = id
	if f.create == nil {
		panic("Unexpected call to CreateHostCatalog")
	}
	return f.create()
}

func (f *fakeRepo) UpdateHost(ctx context.Context, id string, hc repo.Host, masks string) (*repo.Host, error) {
	f.updateParam = masks
	if f.update == nil {
		panic("Unexpected call to UpdateHostCatalog")
	}
	return f.update()
}

func TestDelete(t *testing.T) {
	toMerge := &pbs.DeleteHostRequest{
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
		req      *pbs.DeleteHostRequest
		res      *pbs.DeleteHostResponse
		errCode  codes.Code
	}{
		{
			name:     "Success when exist",
			repoResp: repoReturns(true, nil),
			req:      &pbs.DeleteHostRequest{Id: "exists"},
			res:      &pbs.DeleteHostResponse{Existed: true},
			errCode:  codes.OK,
		},
		{
			name:     "Success when doesn't exist",
			repoResp: repoReturns(false, nil),
			req:      &pbs.DeleteHostRequest{},
			res:      &pbs.DeleteHostResponse{},
			errCode:  codes.OK,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.DeleteHostRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{delete: tc.repoResp}
			s := hosts.NewService(repo)
			got, gErr := s.DeleteHost(context.Background(), req)

			if status.Code(gErr) != tc.errCode {
				t.Errorf("DeleteHost(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}

			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteHost(%q) got response %q, wanted %q", req, got, tc.res)
			}

			if got, want := repo.deleteParam, req.Id; got != want {
				t.Errorf("DeleteHostSet(%+v) results in %q passed to repo, wanted %q", req, got, want)
			}
		})
	}
}

func TestList(t *testing.T) {
	toMerge := &pbs.ListHostsRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
	}

	s := hosts.Service{}
	cases := []struct {
		name    string
		req     *pbs.ListHostsRequest
		res     *pbs.ListHostsResponse
		errCode codes.Code
	}{
		{
			name: "List from a valid catalog id",
			req:  &pbs.ListHostsRequest{},
			// TODO: Update this when the List method is implemented
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Non Existant Host Catalog",
			req:     &pbs.ListHostsRequest{HostCatalogId: "this doesnt exist"},
			res:     nil,
			errCode: codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.ListHostsRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.ListHosts(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("ListHosts(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("ListHosts(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}

func TestGet(t *testing.T) {
	var err error
	toMerge := &pbs.GetHostRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
	}
	rHost := &repo.Host{
		ID:           "requested id",
		FriendlyName: "friendlyname",
		CreatedTime:  time.Now(),
		UpdatedTime:  time.Now(),
	}

	pHost := &pb.Host{
		FriendlyName: &wrappers.StringValue{Value: rHost.FriendlyName},
	}
	if pHost.CreatedTime, err = ptypes.TimestampProto(rHost.CreatedTime); err != nil {
		t.Fatalf("Failed to parse CreatedTime timestamp: %v", err)
	}
	if pHost.UpdatedTime, err = ptypes.TimestampProto(rHost.UpdatedTime); err != nil {
		t.Fatalf("Failed to parse CreatedTime timestamp: %v", err)
	}

	repoReturns := func(h *repo.Host, err error) func() (*repo.Host, error) {
		return func() (*repo.Host, error) { return h, err }
	}

	cases := []struct {
		name     string
		repoResp func() (*repo.Host, error)
		req      *pbs.GetHostRequest
		res      *pbs.GetHostResponse
		errCode  codes.Code
	}{
		{
			name:     "Host Doesn't exist",
			repoResp: repoReturns(nil, nil),
			req:      &pbs.GetHostRequest{},
			res:      nil,
			errCode:  codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetHostRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{lookup: tc.repoResp}
			s := hosts.NewService(repo)
			got, gErr := s.GetHost(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("GetHost(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("GetHost(%q) got response %q, wanted %q", req, got, tc.res)
			}

			if got, want := repo.lookupParam, req.Id; got != want {
				t.Errorf("GetHost(%+v) results in %q passed to repo, wanted %q", req, got, want)
			}
		})
	}
}

func TestUpdate(t *testing.T) {
	toMerge := &pbs.UpdateHostRequest{
		OrgId:         "1",
		ProjectId:     "2",
		HostCatalogId: "3",
	}

	s := hosts.Service{}
	cases := []struct {
		name    string
		req     *pbs.UpdateHostRequest
		res     *pbs.UpdateHostResponse
		errCode codes.Code
	}{
		// TODO: These cases need to be updated as the handlers get implemented.
		{
			name:    "Default request",
			req:     &pbs.UpdateHostRequest{},
			res:     nil,
			errCode: codes.Unimplemented,
		},
		{
			name: "Non Existant Host Catalog",
			req:  &pbs.UpdateHostRequest{HostCatalogId: "this doesnt exist"},
			// The response and error will need to change when this is implemented to be a 404 error
			res:     nil,
			errCode: codes.Unimplemented,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.UpdateHostRequest)
			proto.Merge(req, tc.req)
			got, gErr := s.UpdateHost(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("UpdateHost(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("UpdateHost(%q) got response %q, wanted %q", req, got, tc.res)
			}
		})
	}
}
