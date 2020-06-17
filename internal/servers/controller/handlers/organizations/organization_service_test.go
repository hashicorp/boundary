package organizations_test

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	pb "github.com/hashicorp/watchtower/internal/gen/controller/api/resources/scopes"
	pbs "github.com/hashicorp/watchtower/internal/gen/controller/api/services"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/servers/controller/handlers/organizations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createDefaultOrganizationAndRepo(t *testing.T) (*iam.Scope, func() (*iam.Repository, error)) {
	t.Helper()
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
	org, repo := createDefaultOrganizationAndRepo(t)
	toMerge := &pbs.GetOrganizationRequest{
		Id: org.GetPublicId(),
	}

	pOrganization := &pb.Organization{
		Id:          org.GetPublicId(),
		Name:        &wrapperspb.StringValue{Value: org.GetName()},
		Description: &wrapperspb.StringValue{Value: org.GetDescription()},
		CreatedTime: org.CreateTime.GetTimestamp(),
		UpdatedTime: org.UpdateTime.GetTimestamp(),
	}

	cases := []struct {
		name    string
		req     *pbs.GetOrganizationRequest
		res     *pbs.GetOrganizationResponse
		errCode codes.Code
	}{
		{
			name:    "Get an Existing organization",
			req:     &pbs.GetOrganizationRequest{Id: org.GetPublicId()},
			res:     &pbs.GetOrganizationResponse{Item: pOrganization},
			errCode: codes.OK,
		},
		{
			name:    "Get a non existing organization",
			req:     &pbs.GetOrganizationRequest{Id: iam.OrganizationScope.Prefix() + "_DoesntExis"},
			res:     nil,
			errCode: codes.NotFound,
		},
		{
			name:    "Wrong id prefix",
			req:     &pbs.GetOrganizationRequest{Id: "j_1234567890"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
		{
			name:    "space in id",
			req:     &pbs.GetOrganizationRequest{Id: iam.OrganizationScope.Prefix() + "_1 23456789"},
			res:     nil,
			errCode: codes.InvalidArgument,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := proto.Clone(toMerge).(*pbs.GetOrganizationRequest)
			proto.Merge(req, tc.req)

			s, err := organizations.NewService(repo)
			require.NoError(err, "Couldn't create new project service.")

			got, gErr := s.GetOrganization(context.Background(), req)
			assert.Equal(tc.errCode, status.Code(gErr), "GetOrganization(%+v) got error %v, wanted %v", req, gErr, tc.errCode)
			assert.True(proto.Equal(got, tc.res), "GetOrganization(%q) got response %q, wanted %q", req, got, tc.res)
		})
	}
}
