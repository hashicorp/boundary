package scopeids_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/groups"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/db"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	authpb "github.com/hashicorp/boundary/internal/gen/controller/auth"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/types/scope"
	"github.com/stretchr/testify/require"
)

// This test validates that we can perform recursive listing when there are no
// permissions on the parent scope against which the query is being run, but
// there are on child scopes. We use groups because groups are (one type of
// resource) valid in projects and we want to validate that the initial bugged
// behavior that used role permissions instead of the resource type under test
// is fixed.
func TestListingScopeIds(t *testing.T) {
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
	serversRepoFn := func() (*server.Repository, error) {
		return server.NewRepository(rw, rw, kms)
	}
	s, err := groups.NewService(iamRepoFn)
	require.NoError(t, err)

	sessionsRepoFn := func() (*session.Repository, error) {
		return session.NewRepository(rw, rw, kms)
	}
	sess, err := sessions.NewService(sessionsRepoFn, iamRepoFn)
	require.NoError(t, err)

	tcs := []struct {
		name         string
		globalGrants []string
		orgGrants    []string
		projGrants   []string
		globalGroups int
		orgGroups    int
		projGroups   int
		users        []string
		wantErr      error
		expCount     int
		recurseFrom  string
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
			name:         "perms on global, no groups",
			globalGrants: []string{"id=*;type=group;actions=list,no-op"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			recurseFrom:  "global",
		},
		{
			name:        "perms on org, no groups",
			orgGrants:   []string{"id=*;type=group;actions=list,no-op"},
			projGrants:  []string{"id=*;type=group;actions=read"},
			recurseFrom: "org",
		},
		{
			name:        "perms on project, no groups",
			projGrants:  []string{"id=*;type=group;actions=list,no-op"},
			recurseFrom: "project",
		},
		{
			name:         "perms on global, none in org",
			globalGrants: []string{"id=*;type=group;actions=list,no-op"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     6,
			recurseFrom:  "global",
		},
		{
			name:         "perms on global, none in org, start at org",
			globalGrants: []string{"id=*;type=group;actions=list,no-op"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     5,
			recurseFrom:  "org",
		},
		{
			name:         "perms on global, with org",
			globalGrants: []string{"id=*;type=group;actions=list,no-op"},
			orgGrants:    []string{"id=*;type=group;actions=read"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     9,
			recurseFrom:  "global",
		},
		{
			name:         "perms on global, with org, start at org",
			globalGrants: []string{"id=*;type=group;actions=list,no-op"},
			orgGrants:    []string{"id=*;type=group;actions=read"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     8,
			recurseFrom:  "org",
		},
		{
			name:         "perms on global, start at project",
			globalGrants: []string{"id=*;type=group;actions=list,no-op"},
			orgGrants:    []string{"id=*;type=group;actions=read"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     5,
			recurseFrom:  "project",
		},
		{
			name:         "perms on org, start at global, no read on org",
			orgGrants:    []string{"id=*;type=group;actions=list"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     5,
			recurseFrom:  "global",
		},
		{
			name:         "perms on org, start at global, read on org",
			orgGrants:    []string{"id=*;type=group;actions=list,no-op"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     8,
			recurseFrom:  "global",
		},
		{
			name:         "perms on org, start at org",
			orgGrants:    []string{"id=*;type=group;actions=list,no-op"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     8,
			recurseFrom:  "org",
		},
		{
			name:         "perms on org, start at project",
			orgGrants:    []string{"id=*;type=group;actions=list,no-op"},
			projGrants:   []string{"id=*;type=group;actions=read"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     5,
			recurseFrom:  "project",
		},
		{
			name:         "perms on proj",
			projGrants:   []string{"id=*;type=group;actions=list,no-op"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     5,
			recurseFrom:  "project",
		},
		{
			name:         "perms on proj, start at org",
			projGrants:   []string{"id=*;type=group;actions=list,no-op"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     5,
			recurseFrom:  "org",
		},
		{
			name:         "perms on proj, start at global",
			projGrants:   []string{"id=*;type=group;actions=list,no-op"},
			globalGroups: 1,
			orgGroups:    3,
			projGroups:   5,
			expCount:     5,
			recurseFrom:  "global",
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
				iamRepoFn,
				authTokenRepoFn,
				serversRepoFn,
				kms,
				&authpb.RequestInfo{
					Token:       at.GetToken(),
					TokenFormat: uint32(auth.AuthTokenTypeBearer),
					PublicId:    at.GetPublicId(),
				})

			// Clean up scopes between tests
			defer func() {
				_, err := iamRepo.DeleteScope(ctx, o.GetPublicId())
				require.NoError(err)
			}()

			for i := 0; i < tc.globalGroups; i++ {
				g := iam.TestGroup(t, conn, scope.Global.String())
				defer func() {
					_, err := iamRepo.DeleteGroup(ctx, g.GetPublicId())
					require.NoError(err)
				}()
			}
			for i := 0; i < tc.orgGroups; i++ {
				iam.TestGroup(t, conn, o.GetPublicId())
			}
			for i := 0; i < tc.projGroups; i++ {
				iam.TestGroup(t, conn, p.GetPublicId())
			}

			for i, grants := range [][]string{tc.globalGrants, tc.orgGrants, tc.projGrants} {
				if len(grants) > 0 {
					pubId := scope.Global.String()
					switch i {
					case 1:
						pubId = o.GetPublicId()
					case 2:
						pubId = p.GetPublicId()
					}
					role := iam.TestRole(t, conn, pubId)
					// Clean up global between tests
					if pubId == scope.Global.String() {
						defer func() {
							_, err := iamRepo.DeleteRole(ctx, role.GetPublicId())
							require.NoError(err)
						}()
					}
					for _, grant := range grants {
						iam.TestRoleGrant(t, conn, role.GetPublicId(), grant)
					}
					iam.TestUserRole(t, conn, role.GetPublicId(), at.GetIamUserId())
				}
			}
			var startScope string
			switch tc.recurseFrom {
			case "global":
				startScope = scope.Global.String()
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
			}

			sessOut, err := sess.ListSessions(ctx, &pbs.ListSessionsRequest{
				Recursive: true,
				ScopeId:   startScope,
			})
			require.NoError(err)
			require.NotNil(sessOut)
		})
	}
}
