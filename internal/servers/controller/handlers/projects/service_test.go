package projects_test

import (
	"context"
	"fmt"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
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

type mockRepo struct {
	mock.Mock
}

func (f *mockRepo) LookupScope(ctx context.Context, opt ...iam.Option) (*iam.Scope, error) {
	args := f.Called(ctx, opt)
	return args.Get(0).(*iam.Scope), args.Error(1)
}

func (f *mockRepo) CreateScope(ctx context.Context, hc *iam.Scope, opt ...iam.Option) (*iam.Scope, error) {
	args := f.Called(ctx, hc, opt)
	return args.Get(0).(*iam.Scope), args.Error(1)
}

func (f *mockRepo) UpdateScope(ctx context.Context, hc *iam.Scope, fieldMaskPaths []string, opt ...iam.Option) (*iam.Scope, error) {
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
		Name:        &wrappers.StringValue{Value: rProject.GetName()},
		Description: &wrappers.StringValue{Value: rProject.GetDescription()},
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
		repoIn  *repoIn
		repoOut *repoOut
		req     *pbs.GetProjectRequest
		res     *pbs.GetProjectResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Project",
			repoIn:  &repoIn{iam.WithPublicId(rProject.GetPublicId())},
			repoOut: &repoOut{rProject, nil},
			req:     &pbs.GetProjectRequest{Id: rProject.GetPublicId()},
			res:     &pbs.GetProjectResponse{Item: pProject},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existant Host Catalog",
			repoIn:  &repoIn{iam.WithPublicId("doesnt exist")},
			repoOut: &repoOut{nil, nil},
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

			repo := &mockRepo{}
			// TODO: Validate input option arguments to the repo
			if tc.repoOut != nil {
				repo.On("LookupScope", mock.Anything, mock.Anything).Return(tc.repoOut.scope, tc.repoOut.err)
			}
			s := projects.NewService(repo)

			got, gErr := s.GetProject(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetProject(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestCreate(t *testing.T) {
	toMerge := &pbs.CreateProjectRequest{
		OrgId: "1",
	}

	rProject, err := iam.NewProject("1", iam.WithName("name"), iam.WithDescription("description"))
	if err != nil {
		t.Fatalf("Unable to create project scope: %v", err)
	}

	pProject := &pb.Project{
		Id:          rProject.GetPublicId(),
		Name:        &wrappers.StringValue{Value: rProject.GetName()},
		Description: &wrappers.StringValue{Value: rProject.GetDescription()},
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
		repoIn  *repoIn
		repoOut *repoOut
		req     *pbs.CreateProjectRequest
		res     *pbs.CreateProjectResponse
		errCode codes.Code
	}{
		{
			name:    "Create a valid Project",
			repoOut: &repoOut{rProject, nil},
			req: &pbs.CreateProjectRequest{Item: &pb.Project{
				Name:        &wrappers.StringValue{Value: rProject.GetName()},
				Description: &wrappers.StringValue{Value: rProject.GetDescription()},
			}},
			res: &pbs.CreateProjectResponse{
				Uri:  fmt.Sprintf("orgs/1/projects/%s", rProject.GetPublicId()),
				Item: pProject,
			},
			errCode: codes.OK,
		},
		{
			name:    "Can't specify Id",
			repoOut: nil,
			req: &pbs.CreateProjectRequest{Item: &pb.Project{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Can't specify Created Time",
			repoOut: nil,
			req: &pbs.CreateProjectRequest{Item: &pb.Project{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "Can't specify Update Time",
			repoOut: nil,
			req: &pbs.CreateProjectRequest{Item: &pb.Project{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateProjectRequest)
			proto.Merge(req, tc.req)

			repo := &mockRepo{}
			if tc.repoOut != nil {
				repo.On("CreateScope", mock.Anything, mock.Anything, mock.Anything).Return(tc.repoOut.scope, tc.repoOut.err)
			}
			s := projects.NewService(repo)

			got, gErr := s.CreateProject(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "CreateProject(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	toMerge := &pbs.UpdateProjectRequest{
		OrgId: "1",
		Id:    "2",
	}

	rProject, err := iam.NewProject("1", iam.WithName("name"), iam.WithDescription("description"))
	if err != nil {
		t.Fatalf("Unable to create project scope: %v", err)
	}

	pProject := &pb.Project{
		Id:          rProject.GetPublicId(),
		Name:        &wrappers.StringValue{Value: rProject.GetName()},
		Description: &wrappers.StringValue{Value: rProject.GetDescription()},
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
		repoIn  *repoIn
		repoOut *repoOut
		req     *pbs.UpdateProjectRequest
		res     *pbs.UpdateProjectResponse
		errCode codes.Code
	}{
		{
			name:    "Update an Existing Project",
			repoOut: &repoOut{rProject, nil},
			req: &pbs.UpdateProjectRequest{Item: &pb.Project{
				Name:        &wrappers.StringValue{Value: rProject.GetName()},
				Description: &wrappers.StringValue{Value: rProject.GetDescription()},
			}},
			res: &pbs.UpdateProjectResponse{
				Item: pProject,
			},
			errCode: codes.OK,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateProjectRequest{Item: &pb.Project{
				Id:          "not the same id as in the top level request",
				Name:        &wrappers.StringValue{Value: rProject.GetName()},
				Description: &wrappers.StringValue{Value: rProject.GetDescription()},
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateProjectRequest{Item: &pb.Project{
				Name:        &wrappers.StringValue{Value: rProject.GetName()},
				Description: &wrappers.StringValue{Value: rProject.GetDescription()},
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateProjectRequest{Item: &pb.Project{
				Name:        &wrappers.StringValue{Value: rProject.GetName()},
				Description: &wrappers.StringValue{Value: rProject.GetDescription()},
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateProjectRequest)
			proto.Merge(req, tc.req)

			repo := &mockRepo{}
			if tc.repoOut != nil {
				repo.On("UpdateScope", mock.Anything, mock.Anything, mock.Anything, mock.Anything).Return(tc.repoOut.scope, tc.repoOut.err)
			}
			s := projects.NewService(repo)

			got, gErr := s.UpdateProject(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "UpdateProject(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
