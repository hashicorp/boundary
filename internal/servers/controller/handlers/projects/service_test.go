package projects_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/projects"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultProjectAndRepo(t *testing.T) (*iam.Scope, *iam.Repository) {
	t.Helper()
	require := require.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := conn.Close(); err != nil {
			t.Errorf("Error when closing gorm DB: %v", err)
		}
		if err := cleanup(); err != nil {
			t.Errorf("Error when cleaning up TestSetup: %v", err)
		}
	})
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repo, err := iam.NewRepository(rw, rw, wrap)
	assert.Nil(t, err, "Unable to create new repo")

	// Create a default org and project for our tests.
	o, err := iam.NewOrganization(iam.WithName("default"))
	require.NoError(err, "Could not get new org.")
	oRes, err := repo.CreateScope(context.Background(), o)
	require.NoError(err, "Could not create org scope.")

	p, err := iam.NewProject(oRes.GetPublicId(), iam.WithName("default"), iam.WithDescription("default"))
	require.NoError(err, "Could not get new project.")
	pRes, err := repo.CreateScope(context.Background(), p)
	require.NoError(err, "Could not create new project.")

	return pRes, repo
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	proj, repo := createDefaultProjectAndRepo(t)
	toMerge := &pbs.GetProjectRequest{
		OrgId: proj.GetParentId(),
		Id:    proj.GetPublicId(),
	}

	pProject := &pb.Project{
		Id:          proj.GetPublicId(),
		Name:        &wrapperspb.StringValue{Value: proj.GetName()},
		Description: &wrapperspb.StringValue{Value: proj.GetDescription()},
		CreatedTime: proj.CreateTime.GetTimestamp(),
		UpdatedTime: proj.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetProjectRequest
		res     *pbs.GetProjectResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing Project",
			req:     &pbs.GetProjectRequest{Id: proj.GetPublicId()},
			res:     &pbs.GetProjectResponse{Item: pProject},
			errCode: codes.OK,
		},
		{
			name: "Get a non existant Host Catalog",
			req:  &pbs.GetProjectRequest{Id: "p_DoesntExis"},
			res:  nil,
			// This will be fixed with PR 42
			errCode: codes.NotFound,
		},
		{
			name: "Wrong id prefix",
			req:  &pbs.GetProjectRequest{Id: "j_1234567890"},
			res:  nil,
			// This will be fixed with PR 42
			errCode: codes.InvalidArgument,
		},
		{
			name: "space in id",
			req:  &pbs.GetProjectRequest{Id: "p_1 23456789"},
			res:  nil,
			// This will be fixed with PR 42
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetProjectRequest)
			proto.Merge(req, tc.req)

			s, err := projects.NewService(repo)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.GetProject(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetProject(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	require := require.New(t)
	proj, repo := createDefaultProjectAndRepo(t)

	proj2, err := iam.NewProject(proj.GetParentId())
	require.NoError(err, "Couldn't allocate a second project.")
	proj2, err = repo.CreateScope(context.Background(), proj2)
	require.NoError(err, "Couldn't create new project.")

	s, err := projects.NewService(repo)
	require.NoError(err, "Error when getting new project service.")

	cases := []struct {
		name    string
		req     *pbs.DeleteProjectRequest
		res     *pbs.DeleteProjectResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing Project",
			req: &pbs.DeleteProjectRequest{
				OrgId: proj2.GetParentId(),
				Id:    proj2.GetPublicId(),
			},
			res: &pbs.DeleteProjectResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad project id Project",
			req: &pbs.DeleteProjectRequest{
				OrgId: proj2.GetParentId(),
				Id:    "p_doesntexis",
			},
			res: &pbs.DeleteProjectResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad org id Project",
			req: &pbs.DeleteProjectRequest{
				OrgId: "o_doesntexis",
				Id:    proj2.GetPublicId(),
			},
			res: &pbs.DeleteProjectResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad org formatting",
			req: &pbs.DeleteProjectRequest{
				OrgId: "bad_format",
				Id:    proj2.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad Project Id formatting",
			req: &pbs.DeleteProjectRequest{
				OrgId: proj2.GetParentId(),
				Id:    "bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteProject(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteProject(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteProject(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	proj, repo := createDefaultProjectAndRepo(t)

	s, err := projects.NewService(repo)
	require.NoError(err, "Error when getting new project service")
	req := &pbs.DeleteProjectRequest{
		OrgId: proj.GetParentId(),
		Id:    proj.GetPublicId(),
	}
	got, gErr := s.DeleteProject(context.Background(), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteProject(context.Background(), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	require := require.New(t)
	defaultProj, repo := createDefaultProjectAndRepo(t)
	defaultProjCreated, err := ptypes.Timestamp(defaultProj.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp.")
	toMerge := &pbs.CreateProjectRequest{
		OrgId: defaultProj.GetParentId(),
	}

	cases := []struct {
		name    string
		req     *pbs.CreateProjectRequest
		res     *pbs.CreateProjectResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid Project",
			req: &pbs.CreateProjectRequest{Item: &pb.Project{
				Name:        &wrapperspb.StringValue{Value: "name"},
				Description: &wrapperspb.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateProjectResponse{
				Uri: fmt.Sprintf("orgs/%s/projects/p_", defaultProj.GetParentId()),
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "name"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateProjectRequest{Item: &pb.Project{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateProjectRequest{Item: &pb.Project{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
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

			s, err := projects.NewService(repo)
			require.NoError(err, "Error when getting new project service.")

			got, gErr := s.CreateProject(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				strings.HasPrefix(got.GetUri(), tc.res.Uri)
				strings.HasPrefix(got.GetItem().GetId(), "p_")
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp.")
				// Verify it is a project created after the test setup's default project
				assert.True(gotCreateTime.After(defaultProjCreated), "New project should have been created after default project. Was created %v, which is after %v", gotCreateTime, defaultProjCreated)
				assert.True(gotUpdateTime.After(defaultProjCreated), "New project should have been updated after default project. Was updated %v, which is after %v", gotUpdateTime, defaultProjCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "CreateProject(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	require := require.New(t)
	proj, repo := createDefaultProjectAndRepo(t)
	tested, err := projects.NewService(repo)
	require.NoError(err, "Error when getting new project service.")

	resetProject := func() {
		proj, _, err = repo.UpdateScope(context.Background(), proj, []string{"Name", "Description"})
		require.NoError(err, "Failed to reset the project")
	}

	projCreated, err := ptypes.Timestamp(proj.GetCreateTime().GetTimestamp())
	require.NoError(err, "Error converting proto to timestamp")
	toMerge := &pbs.UpdateProjectRequest{
		OrgId: proj.GetParentId(),
		Id:    proj.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateProjectRequest
		res     *pbs.UpdateProjectResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing Project",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateProjectResponse{
				Item: &pb.Project{
					Id:          proj.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateProjectResponse{
				Item: &pb.Project{
					Id:          proj.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask Is Invalid Argument",
			req: &pbs.UpdateProjectRequest{
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "No Paths in Mask Is Invalid Argument",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask Is Invalid Argument",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "updated name"},
					Description: &wrapperspb.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Project{
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateProjectResponse{
				Item: &pb.Project{
					Id:          proj.GetPublicId(),
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateProjectResponse{
				Item: &pb.Project{
					Id:          proj.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "updated"},
					Description: &wrapperspb.StringValue{Value: "default"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "ignored"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateProjectResponse{
				Item: &pb.Project{
					Id:          proj.GetPublicId(),
					Name:        &wrapperspb.StringValue{Value: "default"},
					Description: &wrapperspb.StringValue{Value: "notignored"},
					CreatedTime: proj.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existant project should result in a NotFound exception but currently results in
		// the repo returning an internal error.
		{
			name: "Update a Non Existing Project",
			req: &pbs.UpdateProjectRequest{
				Id: "p_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.Project{
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateProjectRequest{
				Id: proj.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.Project{
					Id:          "p_somethinge",
					Name:        &wrapperspb.StringValue{Value: "new"},
					Description: &wrapperspb.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.Project{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateProjectRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.Project{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetProject()
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateProjectRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateProject(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateProject(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateProject response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				require.NoError(err, "Error converting proto to timestamp")
				// Verify it is a project updated after it was created
				assert.True(gotUpdateTime.After(projCreated), "Updated project should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, projCreated)

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "UpdateProject(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
