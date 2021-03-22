package scopeids_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers"
	"github.com/hashicorp/boundary/internal/servers/controller/handlers/groups"
	"github.com/stretchr/testify/require"
)

// This test validates that we can perform recursive listing when there are no
// permissions on the parent scope against which the query is being run, but
// there are on child scopes. We use groups because groups are (one type of
// resource) valid in projects and we want to validate that the initial bugged
// behavior that used role permissions instead of the resource type under test
// is fixed.
func TestScopeIds(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrap := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrap)
	iamRepo := iam.TestRepo(t, conn, wrap)
	iamRepoFn := func() (*iam.Repository, error) {
		return iamRepo, nil
	}
	authTokenRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kms)
	}
	serversRepoFn := func() (*servers.Repository, error) {
		return servers.NewRepository(rw, rw, kms)
	}
	s, err := groups.NewService(iamRepoFn)
	require.NoError(t, err)

	tcs := []struct {
		name           string
		globalGrants   []string
		orgGrants      []string
		projGrants     []string
		users          []string
		addCreatedUser bool
		wantErr        error
		expCount       int
		recurseFrom    string
	}{
		{
			name:        "no perms, start at global",
			recurseFrom: "global",
			wantErr:     handlers.ForbiddenError(),
		},
		{
			name:        "no perms, start at org",
			recurseFrom: "org",
			wantErr:     handlers.ForbiddenError(),
		},
		{
			name:        "no perms, start at project",
			recurseFrom: "project",
			wantErr:     handlers.ForbiddenError(),
		},
		{
			name:           "perms on global",
			globalGrants:   []string{"id=*;type=group;actions=list"},
			projGrants:     []string{"id=*;type=group;actions=read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "global",
		},
		{
			name:           "perms on global, start at org",
			globalGrants:   []string{"id=*;type=group;actions=list"},
			projGrants:     []string{"id=*;type=group;actions=read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "org",
		},
		{
			name:           "perms on global, start at project",
			globalGrants:   []string{"id=*;type=group;actions=list"},
			projGrants:     []string{"id=*;type=group;actions=read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "project",
		},
		{
			name:           "perms on org, start at global",
			orgGrants:      []string{"id=*;type=group;actions=list"},
			projGrants:     []string{"id=*;type=group;actions=read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "global",
		},
		{
			name:           "perms on org, start at org",
			orgGrants:      []string{"id=*;type=group;actions=list,read"},
			projGrants:     []string{"id=*;type=group;actions=read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "org",
		},
		{
			name:           "perms on org, start at project",
			orgGrants:      []string{"id=*;type=group;actions=list,read"},
			projGrants:     []string{"id=*;type=group;actions=read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "project",
		},
		{
			name:           "perms on proj",
			projGrants:     []string{"id=*;type=group;actions=list,read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "project",
		},
		{
			name:           "perms on proj, start at org",
			projGrants:     []string{"id=*;type=group;actions=list,read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "org",
		},
		{
			name:           "perms on proj, start at global",
			projGrants:     []string{"id=*;type=group;actions=list,read"},
			addCreatedUser: true,
			expCount:       1,
			recurseFrom:    "global",
		},
	}
	// Each test starts with a new set of scopes and new users/roles, which
	// ensures we don't clash and doesn't require us to deal with cleanup. Plus
	// it means subsequent tests are ensuring that only the scopes that the
	// current user should see are seen.
	for _, tc := range tcs {
		t.Run(tc.name, func(t *testing.T) {
			require := require.New(t)
			o, p := iam.TestScopes(t, iamRepo)
			at := authtoken.TestAuthToken(t, conn, kms, o.GetPublicId())
			ctx := auth.NewVerifierContext(context.Background(),
				nil,
				iamRepoFn,
				authTokenRepoFn,
				serversRepoFn,
				kms,
				auth.RequestInfo{
					Token:       at.GetToken(),
					TokenFormat: auth.AuthTokenTypeBearer,
					PublicId:    at.GetPublicId(),
				})

			// Create a group so that there is at least one value that will come
			// back on success and if we aren't expecting it to come back we are
			// verifying that.
			g := iam.TestGroup(t, conn, p.GetPublicId())

			// If we have users to which to add grants, loop through and create
			// at appropriate org/proj level
			if tc.addCreatedUser {
				tc.users = append(tc.users, at.IamUserId)
			}
			if len(tc.users) > 0 {
				for i, grants := range [][]string{tc.globalGrants, tc.orgGrants, tc.projGrants} {
					if len(grants) > 0 {
						pubId := "global"
						switch i {
						case 1:
							pubId = o.GetPublicId()
						case 2:
							pubId = p.GetPublicId()
						}
						role := iam.TestRole(t, conn, pubId)
						for _, grant := range grants {
							iam.TestRoleGrant(t, conn, role.GetPublicId(), grant)
						}
						for _, user := range tc.users {
							iam.TestUserRole(t, conn, role.GetPublicId(), user)
						}
					}
				}
			}
			var startScope string
			switch tc.recurseFrom {
			case "global":
				startScope = "global"
			case "org":
				startScope = o.GetPublicId()
			case "project":
				startScope = p.GetPublicId()
			default:
				t.Fatal("unknown start scope")
			}
			out, err := s.ListGroups(ctx, &pbs.ListGroupsRequest{
				Recursive: true,
				ScopeId:   startScope,
			})
			if tc.wantErr != nil {
				require.Error(err)
				require.Nil(out)
				require.Equal(tc.wantErr.Error(), err.Error())
			} else {
				require.NoError(err)
				require.NotNil(out)
				require.Len(out.Items, tc.expCount)
				require.Equal(out.Items[0].Id, g.GetPublicId())
			}
		})
	}
}
