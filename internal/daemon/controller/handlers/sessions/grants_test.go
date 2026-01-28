// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sessions_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/ldap"
	"github.com/hashicorp/boundary/internal/authtoken"
	cred "github.com/hashicorp/boundary/internal/credential"
	credstatic "github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	controllerauth "github.com/hashicorp/boundary/internal/daemon/controller/auth"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers"
	"github.com/hashicorp/boundary/internal/daemon/controller/handlers/sessions"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	pbs "github.com/hashicorp/boundary/internal/gen/controller/api/services"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/server"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

// testSession is a wrapper around "session" to help with setting up additional resources and mutating the session states
// to fill in
func testSession(t *testing.T,
	conn *db.DB,
	kmsCache *kms.Kms,
	wrapper wrapping.Wrapper,
	targetRepo *target.Repository,
	sessRepo *session.Repository,
	projectId string, isActive bool,
) *session.Session {
	cats := static.TestCatalogs(t, conn, projectId, 1)
	hosts := static.TestHosts(t, conn, cats[0].PublicId, 1)
	sets := static.TestSets(t, conn, cats[0].PublicId, 1)
	_ = static.TestSetMembers(t, conn, sets[0].PublicId, hosts)
	randomString, err := uuid.GenerateUUID()
	require.NoError(t, err)
	vaultStore := vault.TestCredentialStore(t, conn, wrapper, projectId, fmt.Sprintf("http://vault%s", randomString), fmt.Sprintf("vault-token-%s", randomString), fmt.Sprintf("accessor-%s", randomString))

	libIds := vault.TestCredentialLibraries(t, conn, wrapper, vaultStore.GetPublicId(), globals.UsernamePasswordCredentialType, 2)
	tcpTarget := tcp.TestTarget(context.Background(), t, conn, projectId, randomString, target.WithHostSources([]string{sets[0].GetPublicId()}))
	staticStore := credstatic.TestCredentialStore(t, conn, wrapper, projectId)
	upCreds := credstatic.TestUsernamePasswordCredentials(t, conn, wrapper, randomString, randomString, staticStore.GetPublicId(), projectId, 2)

	ids := target.CredentialSources{
		BrokeredCredentialIds: []string{libIds[0].GetPublicId(), libIds[1].GetPublicId(), upCreds[0].GetPublicId(), upCreds[1].GetPublicId()},
	}
	_, err = targetRepo.AddTargetCredentialSources(context.Background(), tcpTarget.GetPublicId(), tcpTarget.GetVersion(), ids)
	require.NoError(t, err)
	dynamicCreds := []*session.DynamicCredential{
		session.NewDynamicCredential(libIds[0].GetPublicId(), cred.BrokeredPurpose),
		session.NewDynamicCredential(libIds[1].GetPublicId(), cred.BrokeredPurpose),
	}
	staticCreds := []*session.StaticCredential{
		session.NewStaticCredential(upCreds[0].GetPublicId(), cred.BrokeredPurpose),
		session.NewStaticCredential(upCreds[1].GetPublicId(), cred.BrokeredPurpose),
	}
	at := authtoken.TestAuthToken(t, conn, kmsCache, globals.GlobalPrefix)
	uId := at.GetIamUserId()
	worker := server.TestPkiWorker(t, conn, wrapper,
		server.WithNewIdFunc(func(ctx context.Context) (string, error) {
			return server.NewWorkerIdFromScopeAndName(ctx, globals.GlobalPrefix, randomString)
		}),
	)
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:              uId,
		HostId:              hosts[0].GetPublicId(),
		TargetId:            tcpTarget.GetPublicId(),
		HostSetId:           sets[0].GetPublicId(),
		AuthTokenId:         at.GetPublicId(),
		ProjectId:           projectId,
		Endpoint:            "tcp://127.0.0.1:22",
		ExpirationTime:      timestamp.New(time.Now()),
		ConnectionLimit:     10,
		WorkerFilter:        "worker",
		EgressWorkerFilter:  "egress",
		IngressWorkerFilter: "ingress",
		DynamicCredentials:  dynamicCreds,
		StaticCredentials:   staticCreds,
		ProtocolWorkerId:    worker.PublicId,
		CorrelationId:       randomString,
	})

	switch isActive {
	case true:
		session.TestConnection(t, conn, sess.PublicId, "127.0.0.1", 22, "127.0.0.2", 23, "127.0.0.1")
	default:
		_, err := sessRepo.CancelSession(t.Context(), sess.PublicId, sess.Version)
		require.NoError(t, err)
		terminated, err := sessRepo.TerminateCompletedSessions(t.Context())
		require.NoError(t, err)
		require.Equal(t, 1, terminated)
	}
	return sess
}

func TestGrants_ReadActions(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	targetRepo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	require.NoError(t, err)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	sessionRepoFn := func(option ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kmsCache, option...)
	}
	iamRepoFn := func() (*iam.Repository, error) { return iamRepo, nil }

	s, err := sessions.NewService(ctx, sessionRepoFn, iamRepoFn, 100)
	require.NoError(t, err)
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true), iam.WithSkipAdminRoleCreation(true))
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true), iam.WithSkipAdminRoleCreation(true))
	proj3 := iam.TestProject(t, iamRepo, org2.PublicId, iam.WithSkipDefaultRoleCreation(true), iam.WithSkipAdminRoleCreation(true))

	sessionRepo, err := sessionRepoFn()
	require.NoError(t, err)
	proj1Session := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj1.PublicId, true)
	proj1Session2 := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj1.PublicId, true)
	proj2Session := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj2.PublicId, true)
	proj3Session := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj3.PublicId, false)

	type result struct {
		wantErr      error
		outputFields []string
	}

	t.Run("Get", func(t *testing.T) {
		testcases := []struct {
			name           string
			userFunc       func() (*iam.User, auth.Account)
			inputResultMap map[*pbs.GetSessionRequest]result
		}{
			{
				name: "global role descendants grants can read all sessions",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=*;output_fields=id,target_id,scope,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				inputResultMap: map[*pbs.GetSessionRequest]result{
					{Id: proj1Session.PublicId}: {outputFields: []string{globals.IdField, globals.TargetIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					{Id: proj2Session.PublicId}: {outputFields: []string{globals.IdField, globals.TargetIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
					{Id: proj3Session.PublicId}: {outputFields: []string{globals.IdField, globals.TargetIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField}},
				},
			},
			{
				name: "org role individual project grants",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"id=*;type=session;actions=read;output_fields=expiration_time,auth_token_id,user_id,host_set_id,host_ids"},
						GrantScopes: []string{proj1.PublicId},
					},
				}),
				inputResultMap: map[*pbs.GetSessionRequest]result{
					{Id: proj1Session.PublicId}: {outputFields: []string{globals.ExpirationTimeField, globals.AuthTokenIdField, globals.UserIdField, globals.HostSetIdField, globals.HostIdsField}},
					{Id: proj2Session.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: proj3Session.PublicId}: {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "org role children grants",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"id=*;type=session;actions=read;output_fields=version,type,scope_id,endpoint,states,status,certificate,authorized_actions,connections,termination_reason"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				inputResultMap: map[*pbs.GetSessionRequest]result{
					{Id: proj1Session.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: proj2Session.PublicId}: {outputFields: []string{globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField, globals.ConnectionsField}},
					{Id: proj3Session.PublicId}: {outputFields: []string{globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField, globals.TerminationReasonField}},
				},
			},
			{
				name: "proj role this grants",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"id=*;type=session;actions=read;output_fields=version,type,scope_id,endpoint,states,status,certificate,termination_reason,authorized_actions,connections"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputResultMap: map[*pbs.GetSessionRequest]result{
					{Id: proj1Session.PublicId}: {outputFields: []string{globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField, globals.ConnectionsField}},
					{Id: proj2Session.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: proj3Session.PublicId}: {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "multiple project roles",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"id=*;type=session;actions=read;output_fields=authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"id=*;type=session;actions=read;output_fields=version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: proj3.PublicId,
						Grants:      []string{"id=*;type=session;actions=read;output_fields=id"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				inputResultMap: map[*pbs.GetSessionRequest]result{
					{Id: proj1Session.PublicId}: {outputFields: []string{globals.AuthorizedActionsField}},
					{Id: proj2Session.PublicId}: {outputFields: []string{globals.VersionField}},
					{Id: proj3Session.PublicId}: {outputFields: []string{globals.IdField}},
				},
			},
			{
				name: "role with incorrect resource grant",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=worker;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				inputResultMap: map[*pbs.GetSessionRequest]result{
					{Id: proj1Session.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: proj2Session.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: proj3Session.PublicId}: {wantErr: handlers.ForbiddenError()},
				},
			},
			{
				name: "role with incorrect action grant",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=create,update,delete"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				inputResultMap: map[*pbs.GetSessionRequest]result{
					{Id: proj1Session.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: proj2Session.PublicId}: {wantErr: handlers.ForbiddenError()},
					{Id: proj3Session.PublicId}: {wantErr: handlers.ForbiddenError()},
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
				for input, expect := range tc.inputResultMap {
					got, err := s.GetSession(fullGrantAuthCtx, input)
					if expect.wantErr != nil {
						require.ErrorIs(t, expect.wantErr, err)
						continue
					}
					require.NoError(t, err)
					handlers.TestAssertOutputFields(t, got.Item, expect.outputFields)
				}
			})
		}
	})
	t.Run("List", func(t *testing.T) {
		testcases := []struct {
			name              string
			input             *pbs.ListSessionsRequest
			userFunc          func() (*iam.User, auth.Account)
			idOutputFieldsMap map[string][]string
			wantErr           error
		}{
			{
				name: "global list global role descendants grants can read all sessions",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=*;output_fields=id,target_id,scope,created_time,updated_time"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				idOutputFieldsMap: map[string][]string{
					proj1Session.PublicId:  {globals.IdField, globals.TargetIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					proj1Session2.PublicId: {globals.IdField, globals.TargetIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					proj2Session.PublicId:  {globals.IdField, globals.TargetIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField},
					proj3Session.PublicId:  {globals.IdField, globals.TargetIdField, globals.ScopeField, globals.CreatedTimeField, globals.UpdatedTimeField},
				},
			},
			{
				name: "global list org role individual project grants",
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"id=*;type=session;actions=list,read;output_fields=id,expiration_time,auth_token_id,user_id,host_set_id,host_ids"},
						GrantScopes: []string{proj1.PublicId},
					},
				}),
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				idOutputFieldsMap: map[string][]string{
					proj1Session.PublicId:  {globals.IdField, globals.ExpirationTimeField, globals.AuthTokenIdField, globals.UserIdField, globals.HostSetIdField, globals.HostIdsField},
					proj1Session2.PublicId: {globals.IdField, globals.ExpirationTimeField, globals.AuthTokenIdField, globals.UserIdField, globals.HostSetIdField, globals.HostIdsField},
				},
			},
			{
				name: "global list org role children grants",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"id=*;type=session;actions=list,read;output_fields=id,version,type,scope_id,endpoint,states,status,certificate,authorized_actions,termination_reason"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				}),
				idOutputFieldsMap: map[string][]string{
					proj2Session.PublicId: {globals.IdField, globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField},
					proj3Session.PublicId: {globals.IdField, globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField, globals.TerminationReasonField},
				},
			},
			{
				name: "proj role this grants",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"id=*;type=session;actions=list,read;output_fields=id,version,type,scope_id,endpoint,states,status,certificate,termination_reason,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				idOutputFieldsMap: map[string][]string{
					proj1Session.PublicId:  {globals.IdField, globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField},
					proj1Session2.PublicId: {globals.IdField, globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField},
				},
			},
			{
				name: "multiple project roles",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj1.PublicId,
						Grants:      []string{"id=*;type=session;actions=list,no-op;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: proj2.PublicId,
						Grants:      []string{"id=*;type=session;actions=list,no-op;output_fields=id,version"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
					{
						RoleScopeId: proj3.PublicId,
						Grants:      []string{"id=*;type=session;actions=list,no-op;output_fields=id,state"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				idOutputFieldsMap: map[string][]string{
					proj1Session.PublicId:  {globals.IdField, globals.AuthorizedActionsField},
					proj1Session2.PublicId: {globals.IdField, globals.AuthorizedActionsField},
					proj2Session.PublicId:  {globals.IdField, globals.VersionField},
					proj3Session.PublicId:  {globals.IdField, globals.StateField},
				},
			},
			{
				name: "iss 5003 resource id grant should not override all ids",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=*;actions=*;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("ids=%s;actions=*;output_fields=id,version", proj1Session2.PublicId)},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				idOutputFieldsMap: map[string][]string{
					proj1Session.PublicId:  {globals.IdField, globals.AuthorizedActionsField},
					proj1Session2.PublicId: {globals.IdField, globals.AuthorizedActionsField},
					proj2Session.PublicId:  {globals.IdField, globals.AuthorizedActionsField},
					proj3Session.PublicId:  {globals.IdField, globals.AuthorizedActionsField},
				},
			},
			{
				name: "role with incorrect resource grant",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=worker;actions=*"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "role with list permission in global but not projects",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=*"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				}),
				idOutputFieldsMap: map[string][]string{},
			},
			{
				name: "non-recursive list on global scope without grant",
				input: &pbs.ListSessionsRequest{
					ScopeId:           globals.GlobalPrefix,
					Recursive:         true,
					IncludeTerminated: true,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=create,update,delete"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeDescendants},
					},
				}),
				wantErr: handlers.ForbiddenError(),
			},
			{
				name: "non-recursive list children grant",
				input: &pbs.ListSessionsRequest{
					ScopeId: proj2.PublicId,
				},
				userFunc: iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org2.PublicId,
						Grants:      []string{"id=*;type=session;actions=list,no-op;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis, globals.GrantScopeChildren},
					},
				}),
				idOutputFieldsMap: map[string][]string{
					proj2Session.PublicId: {globals.IdField, globals.AuthorizedActionsField},
				},
			},
		}
		for _, tc := range testcases {
			t.Run(tc.name, func(t *testing.T) {
				user, account := tc.userFunc()
				tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
				require.NoError(t, err)
				fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)

				got, err := s.ListSessions(fullGrantAuthCtx, tc.input)
				if tc.wantErr != nil {
					require.ErrorIs(t, tc.wantErr, err)
					return
				}
				require.NoError(t, err)
				require.Len(t, got.Items, len(tc.idOutputFieldsMap))
				for _, item := range got.Items {
					wantOutputFields, ok := tc.idOutputFieldsMap[item.GetId()]
					require.True(t, ok)
					handlers.TestAssertOutputFields(t, item, wantOutputFields)
				}
			})
		}
	})
}

func TestGrants_Cancel(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrap := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrap)
	rw := db.New(conn)
	kmsCache := kms.TestKms(t, conn, wrap)
	targetRepo, err := target.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	require.NoError(t, err)
	atRepo, err := authtoken.NewRepository(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	sessionRepoFn := func(option ...session.Option) (*session.Repository, error) {
		return session.NewRepository(ctx, rw, rw, kmsCache, option...)
	}
	iamRepoFn := func() (*iam.Repository, error) { return iamRepo, nil }

	s, err := sessions.NewService(ctx, sessionRepoFn, iamRepoFn, 100)
	require.NoError(t, err)
	org1, proj1 := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true), iam.WithSkipAdminRoleCreation(true))
	org2, proj2 := iam.TestScopes(t, iamRepo, iam.WithSkipDefaultRoleCreation(true), iam.WithSkipAdminRoleCreation(true))
	proj3 := iam.TestProject(t, iamRepo, org2.PublicId, iam.WithSkipDefaultRoleCreation(true), iam.WithSkipAdminRoleCreation(true))
	sessionRepo, err := sessionRepoFn()

	require.NoError(t, err)
	testcases := []struct {
		name            string
		setup           func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account))
		wantOutputField []string
		wantErr         error
	}{
		{
			name: "global role full grants can cancel",
			setup: func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account)) {
				userFn := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=cancel;output_fields=id,target_id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeDescendants},
					},
				})
				sess := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj2.PublicId, true)
				return sess, userFn
			},
			wantOutputField: []string{globals.IdField, globals.TargetIdField, globals.AuthorizedActionsField},
			wantErr:         nil,
		},
		{
			name: "org role children grants can cancel",
			setup: func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account)) {
				userFn := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: org1.PublicId,
						Grants:      []string{"id=*;type=session;actions=cancel;output_fields=id,version,type,scope_id,endpoint,states"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
				sess := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj1.PublicId, true)
				return sess, userFn
			},
			wantOutputField: []string{globals.IdField, globals.VersionField, globals.TypeField, globals.ScopeIdField, globals.EndpointField, globals.StatesField},
			wantErr:         nil,
		},
		{
			name: "proj role children grants can cancel",
			setup: func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account)) {
				userFn := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: proj3.PublicId,
						Grants:      []string{"id=*;type=session;actions=cancel;output_fields=id,status,certificate,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeThis},
					},
				})
				sess := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj3.PublicId, true)
				return sess, userFn
			},
			wantOutputField: []string{globals.IdField, globals.StatusField, globals.CertificateField, globals.AuthorizedActionsField},
			wantErr:         nil,
		},
		{
			name: "global role specific scope grants can cancel",
			setup: func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account)) {
				userFn := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=cancel;output_fields=id,authorized_actions"},
						GrantScopes: []string{proj2.PublicId},
					},
				})
				sess := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj2.PublicId, true)
				return sess, userFn
			},
			wantOutputField: []string{globals.IdField, globals.AuthorizedActionsField},
			wantErr:         nil,
		},
		{
			name: "global specific scope specific id grants can cancel",
			setup: func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account)) {
				sess := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj2.PublicId, true)
				userFn := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{fmt.Sprintf("id=%s;type=session;actions=cancel;output_fields=id,authorized_actions", sess.PublicId)},
						GrantScopes: []string{proj2.PublicId},
					},
				})
				return sess, userFn
			},
			wantOutputField: []string{globals.IdField, globals.AuthorizedActionsField},
			wantErr:         nil,
		},
		{
			name: "global role children scope grants cannot cancel",
			setup: func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account)) {
				userFn := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=cancel;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
				sess := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj2.PublicId, true)
				return sess, userFn
			},
			wantErr: handlers.ForbiddenError(),
		},
		{
			name: "global role children scope grants cannot cancel",
			setup: func(t *testing.T) (*session.Session, func() (*iam.User, auth.Account)) {
				userFn := iam.TestUserManagedGroupGrantsFunc(t, conn, kmsCache, globals.GlobalPrefix, ldap.TestAuthMethodWithAccountInManagedGroup, []iam.TestRoleGrantsRequest{
					{
						RoleScopeId: globals.GlobalPrefix,
						Grants:      []string{"id=*;type=session;actions=cancel;output_fields=id,authorized_actions"},
						GrantScopes: []string{globals.GrantScopeChildren},
					},
				})
				sess := testSession(t, conn, kmsCache, wrap, targetRepo, sessionRepo, proj2.PublicId, true)
				return sess, userFn
			},
			wantErr: handlers.ForbiddenError(),
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			sess, userFn := tc.setup(t)
			user, account := userFn()

			mySession, _, err := sessionRepo.LookupSession(ctx, sess.PublicId)
			require.NoError(t, err)

			tok, err := atRepo.CreateAuthToken(ctx, user, account.GetPublicId())
			require.NoError(t, err)
			fullGrantAuthCtx := controllerauth.TestAuthContextFromToken(t, conn, wrap, tok, iamRepo)
			got, err := s.CancelSession(fullGrantAuthCtx, &pbs.CancelSessionRequest{
				Id:      mySession.GetPublicId(),
				Version: mySession.Version,
			})
			if tc.wantErr != nil {
				require.ErrorIs(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			handlers.TestAssertOutputFields(t, got.GetItem(), tc.wantOutputField)
		})
	}
}
