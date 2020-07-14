package orgs_test

import (
	"context"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/orgs"
	"github.com/hashicorp/watchtower/internal/types/scope"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultOrgAndRepo(t *testing.T) (*iam.Scope, func() (*iam.Repository, error)) {
	t.Helper()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	oRes, _ := iam.TestScopes(t, conn)
	oRes.Name = "default"
	oRes.Description = "default"
	repo, err := repoFn()
	require.NoError(t, err)
	oRes, _, err = repo.UpdateScope(context.Background(), oRes, []string{"Name", "Description"})
	require.NoError(t, err)
	return oRes, repoFn
}

func TestGet(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)
	org, repo := createDefaultOrgAndRepo(t)
	toMerge := &pbs.GetOrgRequest{
		Id: org.GetPublicId(),
	}

	pOrg := &pb.Org{
		Id:          org.GetPublicId(),
		Name:        &wrapperspb.StringValue{Value: org.GetName()},
		Description: &wrapperspb.StringValue{Value: org.GetDescription()},
		CreatedTime: org.CreateTime.GetTimestamp(),
		UpdatedTime: org.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetOrgRequest
		res     *pbs.GetOrgResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing org",
			req:     &pbs.GetOrgRequest{Id: org.GetPublicId()},
			res:     &pbs.GetOrgResponse{Item: pOrg},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing org",
			req:     &pbs.GetOrgRequest{Id: scope.Org.Prefix() + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetOrgRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetOrgRequest{Id: scope.Org.Prefix() + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetOrgRequest)
			proto.Merge(req, tc.req)

			s, err := orgs.NewService(repo)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.GetOrg(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetOrg(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetOrg(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	repoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, wrap)
	}

	s, err := orgs.NewService(repoFn)
	require.NoError(err)
	ctx := context.Background()
	resp, err := s.ListOrgs(ctx, &pbs.ListOrgsRequest{})
	assert.NoError(err)
	assert.Equal(&pbs.ListOrgsResponse{}, resp)

	var orgs []*pb.Org
	for i := 0; i < 10; i++ {
		o, _ := iam.TestScopes(t, conn)
		orgs = append(orgs, &pb.Org{Id: o.PublicId, CreatedTime: o.GetCreateTime().GetTimestamp(), UpdatedTime: o.GetUpdateTime().GetTimestamp()})
	}
	resp, err = s.ListOrgs(ctx, &pbs.ListOrgsRequest{})
	assert.NoError(err)
	assert.Empty(cmp.Diff(resp, &pbs.ListOrgsResponse{Items: orgs}, protocmp.Transform(), protocmp.SortRepeatedFields(&pbs.ListOrgsResponse{}, "items")))
}
