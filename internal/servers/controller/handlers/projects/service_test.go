package projects_test

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/projects"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/projects"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type fakeRepo struct {
	lookupParam []projects.Option
	listParam   []projects.Option
	deleteParam []projects.Option
	createParam *repo.Project
	updateParam *repo.Project

	lookup func() (*repo.Project, error)
	list   func() ([]repo.Project, error)
	delete func() (bool, error)
	create func() (*repo.Project, error)
	update func() (*repo.Project, error)
}

func (f *fakeRepo) LookupProject(ctx context.Context, opt ...projects.Option) (*repo.Project, error) {
	f.lookupParam = opt
	if f.lookup == nil {
		panic("Unexpected call to LookupProject")
	}
	return f.lookup()
}

func (f *fakeRepo) ListProjects(ctx context.Context, opt ...projects.Option) ([]repo.Project, error) {
	f.listParam = opt
	if f.list == nil {
		panic("Unexpected call to ListProjects")
	}
	return f.list()
}

func (f *fakeRepo) DeleteProject(ctx context.Context, opt ...projects.Option) (bool, error) {
	f.deleteParam = opt
	if f.delete == nil {
		panic("Unexpected call to DeleteProject")
	}
	return f.delete()
}

func (f *fakeRepo) CreateProject(ctx context.Context, hc *repo.Project, opt ...projects.Option) (*repo.Project, error) {
	f.createParam = hc
	if f.create == nil {
		panic("Unexpected call to CreateProject")
	}
	return f.create()
}

func (f *fakeRepo) UpdateProject(ctx context.Context, hc *repo.Project, fieldMaskPaths []string, opt ...projects.Option) (*repo.Project, error) {
	f.updateParam = hc
	if f.update == nil {
		panic("Unexpected call to UpdateProject")
	}
	return f.update()
}

func TestDelete(t *testing.T) {
	toMerge := &pbs.DeleteProjectRequest{
		OrgId: "1",
		Id:    "2",
	}

	repoReturns := func(b bool, err error) func() (bool, error) {
		return func() (bool, error) { return b, err }
	}

	cases := []struct {
		name     string
		repoResp func() (bool, error)
		req      *pbs.DeleteProjectRequest
		res      *pbs.DeleteProjectResponse
		errCode  codes.Code
	}{
		{
			name:     "Delete Existing record",
			repoResp: repoReturns(true, nil),
			req:      &pbs.DeleteProjectRequest{Id: "exists"},
			res:      &pbs.DeleteProjectResponse{Existed: true},
			errCode:  codes.OK,
		},
		{
			name:     "Delete always succeeds even for non existant catalogs",
			repoResp: repoReturns(false, nil),
			req:      &pbs.DeleteProjectRequest{Id: "This doesn't exist."},
			res:      &pbs.DeleteProjectResponse{},
			errCode:  codes.OK,
		},
		{
			name:     "Repo Errors passed on to client",
			repoResp: repoReturns(false, fmt.Errorf("Some Failure")),
			req:      &pbs.DeleteProjectRequest{Id: "exists"},
			res:      nil,
			errCode:  codes.Internal,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.DeleteProjectRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{delete: tc.repoResp}
			s := projects.NewService(repo)

			got, gErr := s.DeleteProject(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("DeleteProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("DeleteProject(%q) got response %q, wanted %q", req, got, tc.res)
			}

			if got, want := repo.deleteParam, []projects.Option{projects.WithPublicId(tc.req.Id)}; !reflect.DeepEqual(got, want) {
				t.Errorf("DeleteProject(%+v) results in %q passed to repo, wanted %q", req, got, want)
			}
		})
	}
}

func TestGet(t *testing.T) {
	var err error
	toMerge := &pbs.GetProjectRequest{
		OrgId: "1",
		Id:    "2",
	}

	rProject := &repo.Project{
		ID:           "requested id",
		FriendlyName: "friendlyname",
		ScopeID:      "scopeid",
		CreatedTime:  time.Now(),
		UpdatedTime:  time.Now(),
	}

	pProject := &pb.Project{
		FriendlyName: &wrappers.StringValue{Value: rProject.FriendlyName},
	}
	if pProject.CreatedTime, err = ptypes.TimestampProto(rProject.CreatedTime); err != nil {
		t.Fatalf("Failed to parse CreatedTime timestamp: %v", err)
	}
	if pProject.UpdatedTime, err = ptypes.TimestampProto(rProject.UpdatedTime); err != nil {
		t.Fatalf("Failed to parse CreatedTime timestamp: %v", err)
	}

	repoReturns := func(h *repo.Project, err error) func() (*repo.Project, error) {
		return func() (*repo.Project, error) { return h, err }
	}

	cases := []struct {
		name     string
		repoResp func() (*repo.Project, error)
		req      *pbs.GetProjectRequest
		res      *pbs.GetProjectResponse
		errCode  codes.Code
	}{
		{
			name:     "Get an Existing Project",
			repoResp: repoReturns(rProject, nil),
			req:      &pbs.GetProjectRequest{Id: "exists"},
			res:      &pbs.GetProjectResponse{Item: pProject},
			errCode:  codes.OK,
		},
		{
			name:     "Get a non existant Host Catalog",
			repoResp: repoReturns(nil, nil),
			req:      &pbs.GetProjectRequest{Id: "doesnt exist"},
			res:      nil,
			errCode:  codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetProjectRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{lookup: tc.repoResp}
			s := projects.NewService(repo)

			got, gErr := s.GetProject(context.Background(), req)
			if status.Code(gErr) != tc.errCode {
				t.Errorf("GetProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			}
			if !proto.Equal(got, tc.res) {
				t.Errorf("GetProject(%q) got response %q, wanted %q", req, got, tc.res)
			}

			if got, want := repo.lookupParam, []projects.Option{projects.WithPublicId(tc.req.Id)}; !reflect.DeepEqual(got, want) {
				t.Errorf("GetProject(%+v) results in %q passed to repo, wanted %q", req, got, want)
			}
		})
	}
}
