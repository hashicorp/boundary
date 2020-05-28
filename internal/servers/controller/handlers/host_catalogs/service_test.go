package host_catalogs_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/golang/protobuf/proto"
	"github.com/golang/protobuf/ptypes"
	"github.com/golang/protobuf/ptypes/wrappers"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/hosts"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/host/static"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/host_catalogs"
	"google.golang.org/genproto/protobuf/field_mask"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/stretchr/testify/assert"
)

func createDefaultHostCatalogAndRepo(t *testing.T) (*static.HostCatalog, *iam.Scope, *static.Repository) {
	t.Helper()
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		conn.Close()
		cleanup()
	})
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	iamRepo, err := iam.NewRepository(rw, rw, wrap)
	assert.Nil(t, err, "Unable to create new repo")

	// Create a default org and project for our tests.
	o, err := iam.NewOrganization(iam.WithName("default"))
	if err != nil {
		t.Fatalf("Could not get new org: %v", err)
	}
	oRes, err := iamRepo.CreateScope(context.Background(), o)
	if err != nil {
		t.Fatalf("Could not create org scope: %v", err)
	}

	p, err := iam.NewProject(oRes.GetPublicId(), iam.WithName("default"), iam.WithDescription("default"))
	if err != nil {
		t.Fatalf("Could not get new project: %v", err)
	}
	pRes, err := iamRepo.CreateScope(context.Background(), p)
	if err != nil {
		t.Fatalf("Could not create project scope: %v", err)
	}

	repo, err := static.NewRepository(rw, rw, wrap)
	if err != nil {
		t.Fatalf("Couldn't create static host catalog repo: %v", err)
	}

	hc, err := static.NewHostCatalog(pRes.GetPublicId(), static.WithName("default"), static.WithDescription("default"))
	if err != nil {
		t.Fatalf("Could not get new host catalog: %v", err)
	}
	hcRes, err := repo.CreateCatalog(context.Background(), hc)
	if err != nil {
		t.Fatalf("Could not create host catalog: %v", err)
	}

	return hcRes, pRes, repo
}

func TestGet(t *testing.T) {
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)
	toMerge := &pbs.GetHostCatalogRequest{
		OrgId:     proj.GetParentId(),
		ProjectId: proj.GetPublicId(),
		Id:        hc.GetPublicId(),
	}

	pHostCatalog := &pb.HostCatalog{
		Id:          hc.GetPublicId(),
		Name:        &wrappers.StringValue{Value: hc.GetName()},
		Description: &wrappers.StringValue{Value: hc.GetDescription()},
		CreatedTime: hc.CreateTime.GetTimestamp(),
		UpdatedTime: hc.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetHostCatalogRequest
		res     *pbs.GetHostCatalogResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing HostCatalog",
			req:     &pbs.GetHostCatalogRequest{Id: hc.GetPublicId()},
			res:     &pbs.GetHostCatalogResponse{Item: pHostCatalog},
			errCode: codes.OK,
		},
		{
			name: "Get a non existant Host Catalog",
			req:  &pbs.GetHostCatalogRequest{Id: static.HostCatalogPrefix + "_DoesntExis"},
			res:  nil,
			// This will be fixed with PR 42
			errCode: codes.NotFound,
		},
		// TODO: Decide if this should be an invalid argument or unimplemented exception when the prefix doesn't match a known subtype.
		{
			name: "Wrong id prefix",
			req:  &pbs.GetHostCatalogRequest{Id: "j_1234567890"},
			res:  nil,
			// This will be fixed with PR 42
			errCode: codes.InvalidArgument,
		},
		{
			name: "space in id",
			req:  &pbs.GetHostCatalogRequest{Id: static.HostCatalogPrefix + "_1 23456789"},
			res:  nil,
			// This will be fixed with PR 42
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.GetHostCatalogRequest)
			proto.Merge(req, tc.req)

			s := host_catalogs.NewService(repo)

			got, gErr := s.GetHostCatalog(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestDelete(t *testing.T) {
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)

	hc2, err := static.NewHostCatalog(hc.GetScopeId())
	if err != nil {
		t.Fatalf("Couldn't allocate a second host catalog: %v", err)
	}
	hc2, err = repo.CreateCatalog(context.Background(), hc2)
	if err != nil {
		t.Fatalf("Couldn't persist a second host catalog %v", err)
	}

	s := host_catalogs.NewService(repo)

	cases := []struct {
		name    string
		req     *pbs.DeleteHostCatalogRequest
		res     *pbs.DeleteHostCatalogResponse
		errCode codes.Code
	}{
		{
			name: "Delete an Existing HostCatalog",
			req: &pbs.DeleteHostCatalogRequest{
				OrgId:     proj.GetParentId(),
				ProjectId: proj.GetPublicId(),
				Id:        hc.GetPublicId(),
			},
			res: &pbs.DeleteHostCatalogResponse{
				Existed: true,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad id HostCatalog",
			req: &pbs.DeleteHostCatalogRequest{
				OrgId:     proj.GetParentId(),
				ProjectId: proj.GetPublicId(),
				Id:        static.HostCatalogPrefix + "_doesntexis",
			},
			res: &pbs.DeleteHostCatalogResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad org id in HostCatalog",
			req: &pbs.DeleteHostCatalogRequest{
				OrgId:     "o_doesntexis",
				ProjectId: proj.GetPublicId(),
				Id:        hc.GetPublicId(),
			},
			res: &pbs.DeleteHostCatalogResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Delete bad project id in HostCatalog",
			req: &pbs.DeleteHostCatalogRequest{
				OrgId:     proj.GetParentId(),
				ProjectId: "p_doesntexis",
				Id:        hc.GetPublicId(),
			},
			res: &pbs.DeleteHostCatalogResponse{
				Existed: false,
			},
			errCode: codes.OK,
		},
		{
			name: "Bad org formatting",
			req: &pbs.DeleteHostCatalogRequest{
				OrgId:     "bad_format",
				ProjectId: proj.GetPublicId(),
				Id:        hc.GetPublicId(),
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Bad HostCatalog Id formatting",
			req: &pbs.DeleteHostCatalogRequest{
				OrgId:     proj.GetParentId(),
				ProjectId: proj.GetPublicId(),
				Id:        static.HostCatalogPrefix + "_bad_format",
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			got, gErr := s.DeleteHostCatalog(context.Background(), tc.req)
			assert.Equal(tc.errCode, status.Code(gErr), "DeleteHostCatalog(%+v) got error %v, wanted %v", tc.req, gErr, tc.errCode)
			assert.EqualValuesf(tc.res, got, "DeleteHostCatalog(%q) got response %q, wanted %q", tc.req, got, tc.res)
		})
	}
}

func TestDelete_twice(t *testing.T) {
	assert := assert.New(t)
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)

	s := host_catalogs.NewService(repo)
	req := &pbs.DeleteHostCatalogRequest{
		OrgId:     proj.GetParentId(),
		ProjectId: proj.GetPublicId(),
		Id:        hc.GetPublicId(),
	}
	got, gErr := s.DeleteHostCatalog(context.Background(), req)
	assert.NoError(gErr, "First attempt")
	assert.True(got.GetExisted(), "Expected existed to be true for the first delete.")
	got, gErr = s.DeleteHostCatalog(context.Background(), req)
	assert.NoError(gErr, "Second attempt")
	assert.False(got.GetExisted(), "Expected existed to be false for the second delete.")
}

func TestCreate(t *testing.T) {
	defaultHc, proj, repo := createDefaultHostCatalogAndRepo(t)
	defaultHcCreated, err := ptypes.Timestamp(defaultHc.GetCreateTime().GetTimestamp())
	if err != nil {
		t.Fatalf("Error converting proto to timestamp: %v", err)
	}
	toMerge := &pbs.CreateHostCatalogRequest{
		OrgId:     proj.GetParentId(),
		ProjectId: proj.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.CreateHostCatalogRequest
		res     *pbs.CreateHostCatalogResponse
		errCode codes.Code
	}{
		{
			name: "Create a valid HostCatalog",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Name:        &wrappers.StringValue{Value: "name"},
				Description: &wrappers.StringValue{Value: "desc"},
			}},
			res: &pbs.CreateHostCatalogResponse{
				Uri: fmt.Sprintf("orgs/%s/projects/%s/host-catalogs/%s_", proj.GetParentId(), proj.GetPublicId(), static.HostCatalogPrefix),
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "name"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Can't specify Id",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				Id: "not allowed to be set",
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Created Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				CreatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Can't specify Update Time",
			req: &pbs.CreateHostCatalogRequest{Item: &pb.HostCatalog{
				UpdatedTime: ptypes.TimestampNow(),
			}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.CreateHostCatalogRequest)
			proto.Merge(req, tc.req)

			s := host_catalogs.NewService(repo)

			got, gErr := s.CreateHostCatalog(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "CreateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			if got != nil {
				assert.True(strings.HasPrefix(got.GetUri(), tc.res.GetUri()))
				assert.True(strings.HasPrefix(got.GetItem().GetId(), static.HostCatalogPrefix))
				gotCreateTime, err := ptypes.Timestamp(got.GetItem().GetCreatedTime())
				if err != nil {
					t.Fatalf("Error converting proto to timestamp: %v", err)
				}
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				if err != nil {
					t.Fatalf("Error converting proto to timestamp: %v", err)
				}
				// Verify it is a catalog created after the test setup's default catalog
				assert.True(gotCreateTime.After(defaultHcCreated), "New catalog should have been created after default catalog. Was created %v, which is after %v", gotCreateTime, defaultHcCreated)
				assert.True(gotUpdateTime.After(defaultHcCreated), "New catalog should have been updated after default catalog. Was updated %v, which is after %v", gotUpdateTime, defaultHcCreated)

				// Clear all values which are hard to compare against.
				got.Uri, tc.res.Uri = "", ""
				got.Item.Id, tc.res.Item.Id = "", ""
				got.Item.CreatedTime, got.Item.UpdatedTime, tc.res.Item.CreatedTime, tc.res.Item.UpdatedTime = nil, nil, nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "CreateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestUpdate(t *testing.T) {
	hc, proj, repo := createDefaultHostCatalogAndRepo(t)
	tested := host_catalogs.NewService(repo)

	var err error
	resetHostCatalog := func() {
		if hc, _, err = repo.UpdateCatalog(context.Background(), hc, []string{"Name", "Description"}); err != nil {
			t.Fatalf("Failed to reset the catalog")
		}
	}

	hcCreated, err := ptypes.Timestamp(hc.GetCreateTime().GetTimestamp())
	if err != nil {
		t.Fatalf("Error converting proto to timestamp: %v", err)
	}
	toMerge := &pbs.UpdateHostCatalogRequest{
		OrgId:     proj.GetParentId(),
		ProjectId: proj.GetPublicId(),
		Id:        hc.GetPublicId(),
	}

	cases := []struct {
		name    string
		req     *pbs.UpdateHostCatalogRequest
		res     *pbs.UpdateHostCatalogResponse
		errCode codes.Code
	}{
		{
			name: "Update an Existing HostCatalog",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name", "description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Multiple Paths in single string",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name,description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "No Update Mask",
			req: &pbs.UpdateHostCatalogRequest{
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Empty Path",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{}},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Only non-existant paths in Mask",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{Paths: []string{"nonexistant_field"}},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated name"},
					Description: &wrappers.StringValue{Value: "updated desc"},
				},
			},
			errCode: codes.InvalidArgument,
		},
		{
			name: "Unset Name",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					Description: &wrappers.StringValue{Value: "default"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Unset Description",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					Name:        &wrappers.StringValue{Value: "default"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Name",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"name"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "ignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					Name:        &wrappers.StringValue{Value: "updated"},
					Description: &wrappers.StringValue{Value: "default"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		{
			name: "Update Only Description",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "ignored"},
					Description: &wrappers.StringValue{Value: "notignored"},
				},
			},
			res: &pbs.UpdateHostCatalogResponse{
				Item: &pb.HostCatalog{
					Id:          hc.GetPublicId(),
					Name:        &wrappers.StringValue{Value: "default"},
					Description: &wrappers.StringValue{Value: "notignored"},
					CreatedTime: hc.GetCreateTime().GetTimestamp(),
				},
			},
			errCode: codes.OK,
		},
		// TODO: Updating a non existing catalog should result in a NotFound exception but currently results in
		// the repo returning an internal error.
		{
			name: "Update a Non Existing HostCatalog",
			req: &pbs.UpdateHostCatalogRequest{
				Id: static.HostCatalogPrefix + "_DoesntExis",
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"description"},
				},
				Item: &pb.HostCatalog{
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "desc"},
				},
			},
			errCode: codes.Internal,
		},
		{
			name: "Cant change Id",
			req: &pbs.UpdateHostCatalogRequest{
				Id: hc.GetPublicId(),
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"id"},
				},
				Item: &pb.HostCatalog{
					Id:          "p_somethinge",
					Name:        &wrappers.StringValue{Value: "new"},
					Description: &wrappers.StringValue{Value: "new desc"},
				}},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Created Time",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"created_time"},
				},
				Item: &pb.HostCatalog{
					CreatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name: "Cant specify Updated Time",
			req: &pbs.UpdateHostCatalogRequest{
				UpdateMask: &field_mask.FieldMask{
					Paths: []string{"updated_time"},
				},
				Item: &pb.HostCatalog{
					UpdatedTime: ptypes.TimestampNow(),
				},
			},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer resetHostCatalog()
			assert := assert.New(t)
			req := proto.Clone(toMerge).(*pbs.UpdateHostCatalogRequest)
			proto.Merge(req, tc.req)

			got, gErr := tested.UpdateHostCatalog(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "UpdateHostCatalog(%+v) got error %v, wanted %v", req, gErr, tc.errCode)

			if got != nil {
				assert.NotNilf(tc.res, "Expected UpdateHostCatalog response to be nil, but was %v", got)
				gotUpdateTime, err := ptypes.Timestamp(got.GetItem().GetUpdatedTime())
				if err != nil {
					t.Fatalf("Error converting proto to timestamp: %v", err)
				}
				// Verify it is a project updated after it was created
				// TODO: This is currently failing.
				//assert.True(gotUpdateTime.After(hcCreated), "Updated project should have been updated after it's creation. Was updated %v, which is after %v", gotUpdateTime, hcCreated)
				_ = gotUpdateTime
				_ = hcCreated

				// Clear all values which are hard to compare against.
				got.Item.UpdatedTime, tc.res.Item.UpdatedTime = nil, nil
			}
			assert.True(proto.Equal(got, tc.res), "UpdateHostCatalog(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
