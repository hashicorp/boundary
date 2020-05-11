package projects_test

import (
	"context"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes/wrappers"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/projects"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/projects"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type fakeRepo struct {
	mock.Mock
}

func (f *fakeRepo) LookupScope(ctx context.Context, opt ...iam.Option) (*iam.Scope, error) {
	args := f.Called(ctx, opt)
	return args.Get(0).(*iam.Scope), args.Error(1)
}

func (f *fakeRepo) CreateScope(ctx context.Context, hc *iam.Scope, opt ...iam.Option) (*iam.Scope, error) {
	args := f.Called(ctx, hc, opt)
	return args.Get(0).(*iam.Scope), args.Error(1)
}

func (f *fakeRepo) UpdateScope(ctx context.Context, hc *iam.Scope, fieldMaskPaths []string, opt ...iam.Option) (*iam.Scope, error) {
	args := f.Called(ctx, hc, fieldMaskPaths, opt)
	return args.Get(0).(*iam.Scope), args.Error(1)
}

func TestGet(t *testing.T) {
	toMerge := &pbs.GetProjectRequest{
		OrgId: "1",
		Id:    "2",
	}

	rProject, err := iam.NewProject("1", iam.WithName("exists"), iam.WithDescription("description"))
	if err != nil {
		t.Fatalf("Unable to create project scope: %v", err)
	}

	pProject := &pb.Project{
		Id:          rProject.GetPublicId(),
		Name:        &wrappers.StringValue{Value: rProject.Name},
		CreatedTime: rProject.CreateTime.GetTimestamp(),
		UpdatedTime: rProject.UpdateTime.GetTimestamp(),
	}

	type repoIn []iam.Option
	type repoOut struct {
		scope *iam.Scope
		err   error
	}

	cases := []struct {
		name    string
		repoIn  repoIn
		repoOut repoOut
		req     *pbs.GetProjectRequest
		res     *pbs.GetProjectResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Project",
			repoIn:  repoIn{iam.WitPublicId(rProject.GetPublicId())},
			repoOut: repoOut{rProject, nil},
			req:     &pbs.GetProjectRequest{Id: rProject.GetPublicId()},
			res:     &pbs.GetProjectResponse{Item: pProject},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant Host Catalog",
			repoIn:  repoIn{iam.WitPublicId("doesnt exist")},
			repoOut: repoOut{nil, nil},
			req:     &pbs.GetProjectRequest{Id: "doesnt exist"},
			res:     nil,
			errCode: codes.NotFound,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.GetProjectRequest)
			proto.Merge(req, tc.req)

			repo := &fakeRepo{}
			repo.On("LookupScope", mock.Anything, mock.Anything).Return(tc.repoOut.scope, tc.repoOut.err)
			s := projects.NewService(repo)

			got, gErr := s.GetProject(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetProject(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

//
// func TestCreate(t *testing.T) {
// 	toMerge := &pbs.GetProjectRequest{
// 		OrgId: "1",
// 		Id:    "2",
// 	}
//
// 	rProject, err := iam.NewProject("1", iam.WithName("name"), iam.WithDescription("description"))
// 	if err != nil {
// 		t.Fatalf("Unable to create project scope: %v", err)
// 	}
//
// 	pProject := &pb.Project{
// 		Name: &wrappers.StringValue{Value: rProject.Name},
// 		CreatedTime: rProject.CreateTime.GetTimestamp(),
// 		UpdatedTime: rProject.UpdateTime.GetTimestamp(),
// 	}
//
// 	repoReturns := func(h *iam.Scope, err error) func() (*iam.Scope, error) {
// 		return func() (*iam.Scope, error) { return h, err }
// 	}
//
// 	cases := []struct {
// 		name     string
// 		repoResp func() (*iam.Scope, error)
// 		req      *pbs.GetProjectRequest
// 		res      *pbs.GetProjectResponse
// 		errCode  codes.Code
// 	}{
// 		{
// 			name:     "Get an Existing Project",
// 			repoResp: repoReturns(rProject, nil),
// 			req:      &pbs.GetProjectRequest{Id: "exists"},
// 			res:      &pbs.GetProjectResponse{Item: pProject},
// 			errCode:  codes.OK,
// 		},
// 		{
// 			name:     "Get a non existant Host Catalog",
// 			repoResp: repoReturns(nil, nil),
// 			req:      &pbs.GetProjectRequest{Id: "doesnt exist"},
// 			res:      nil,
// 			errCode:  codes.NotFound,
// 		},
// 	}
// 	for _, tc := range cases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			req := proto.Clone(toMerge).(*pbs.GetProjectRequest)
// 			proto.Merge(req, tc.req)
//
// 			repo := &fakeRepo{lookup: tc.repoResp}
// 			s := projects.NewService(repo)
//
// 			got, gErr := s.GetProject(context.Background(), req)
// 			if status.Code(gErr) != tc.errCode {
// 				t.Errorf("GetProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
// 			}
// 			if !proto.Equal(got, tc.res) {
// 				t.Errorf("GetProject(%q) got response %q, wanted %q", req, got, tc.res)
// 			}
//
// 			if got, want := repo.lookupParam, []iam.Option{iam.WitPublicId(tc.req.Id)}; !reflect.DeepEqual(got, want) {
// 				t.Errorf("GetProject(%+v) results in %q passed to repo, wanted %q", req, got, want)
// 			}
// 		})
// 	}
// }
//
// func TestUpdate(t *testing.T) {
// 	toMerge := &pbs.GetProjectRequest{
// 		OrgId: "1",
// 		Id:    "2",
// 	}
//
// 	rProject, err := iam.NewProject("1", iam.WithName("name"), iam.WithDescription("description"))
// 	if err != nil {
// 		t.Fatalf("Unable to create project scope: %v", err)
// 	}
//
// 	pProject := &pb.Project{
// 		Name: &wrappers.StringValue{Value: rProject.Name},
// 		CreatedTime: rProject.CreateTime.GetTimestamp(),
// 		UpdatedTime: rProject.UpdateTime.GetTimestamp(),
// 	}
//
// 	repoReturns := func(h *iam.Scope, err error) func() (*iam.Scope, error) {
// 		return func() (*iam.Scope, error) { return h, err }
// 	}
//
// 	cases := []struct {
// 		name     string
// 		repoResp func() (*iam.Scope, error)
// 		req      *pbs.GetProjectRequest
// 		res      *pbs.GetProjectResponse
// 		errCode  codes.Code
// 	}{
// 		{
// 			name:     "Get an Existing Project",
// 			repoResp: repoReturns(rProject, nil),
// 			req:      &pbs.GetProjectRequest{Id: "exists"},
// 			res:      &pbs.GetProjectResponse{Item: pProject},
// 			errCode:  codes.OK,
// 		},
// 		{
// 			name:     "Get a non existant Host Catalog",
// 			repoResp: repoReturns(nil, nil),
// 			req:      &pbs.GetProjectRequest{Id: "doesnt exist"},
// 			res:      nil,
// 			errCode:  codes.NotFound,
// 		},
// 	}
// 	for _, tc := range cases {
// 		t.Run(tc.name, func(t *testing.T) {
// 			req := proto.Clone(toMerge).(*pbs.GetProjectRequest)
// 			proto.Merge(req, tc.req)
//
// 			repo := &fakeRepo{lookup: tc.repoResp}
// 			s := projects.NewService(repo)
//
// 			got, gErr := s.GetProject(context.Background(), req)
// 			if status.Code(gErr) != tc.errCode {
// 				t.Errorf("GetProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
// 			}
// 			if !proto.Equal(got, tc.res) {
// 				t.Errorf("GetProject(%q) got response %q, wanted %q", req, got, tc.res)
// 			}
//
// 			if got, want := repo.lookupParam, []iam.Option{iam.WitPublicId(tc.req.Id)}; !reflect.DeepEqual(got, want) {
// 				t.Errorf("GetProject(%+v) results in %q passed to repo, wanted %q", req, got, want)
// 			}
// 		})
// 	}
// }
