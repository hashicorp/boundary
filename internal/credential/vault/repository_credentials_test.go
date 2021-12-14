package vault_test

import (
	"context"
	"path"
	"testing"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRepository_IssueCredentials(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	v := vault.NewTestVaultServer(t, vault.WithDockerNetwork(true), vault.WithTestVaultTLS(vault.TestClientTLS))
	v.MountDatabase(t)
	v.MountPKI(t)
	v.AddKVPolicy(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kms := kms.TestKms(t, conn, wrapper)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := vault.NewRepository(rw, rw, kms, sche)
	require.NoError(t, err)
	require.NotNil(t, repo)
	err = vault.RegisterJobs(ctx, sche, rw, rw, kms)
	require.NoError(t, err)

	_, token := v.CreateToken(t, vault.WithPolicies([]string{"default", "boundary-controller", "database", "pki", "secret"}))

	// Create valid user password KV secret
	v.CreateKVSecret(t, "my-secret", []byte(`{"data":{"username":"user","password":"pass"}}`))

	var opts []vault.Option
	opts = append(opts, vault.WithCACert(v.CaCert))
	clientCert, err := vault.NewClientCertificate(v.ClientCert, v.ClientKey)
	require.NoError(t, err)
	opts = append(opts, vault.WithClientCert(clientCert))

	credStoreIn, err := vault.NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token), opts...)
	assert.NoError(t, err)
	require.NotNil(t, credStoreIn)
	origStore, err := repo.CreateCredentialStore(ctx, credStoreIn)
	assert.NoError(t, err)
	require.NotNil(t, origStore)

	type libT int
	const (
		libDB libT = iota
		libUsrPassDB
		libErrUsrPassDB
		libPKI
		libErrPKI
		libUsrPassKV
		libErrKV
	)

	libs := make(map[libT]string)
	{
		libPath := path.Join("database", "creds", "opened")
		libIn, err := vault.NewCredentialLibrary(origStore.GetPublicId(), libPath)
		assert.NoError(t, err)
		require.NotNil(t, libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(t, err)
		require.NotNil(t, lib)
		libs[libDB] = lib.GetPublicId()
	}
	{
		libPath := path.Join("pki", "issue", "boundary")
		libIn, err := vault.NewCredentialLibrary(origStore.GetPublicId(), libPath, vault.WithMethod(vault.MethodPost), vault.WithRequestBody([]byte(`{"common_name":"boundary.com"}`)))
		assert.NoError(t, err)
		require.NotNil(t, libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(t, err)
		require.NotNil(t, lib)
		libs[libPKI] = lib.GetPublicId()
	}
	{

		libPath := path.Join("pki", "issue", "boundary")
		libIn, err := vault.NewCredentialLibrary(origStore.GetPublicId(), libPath, vault.WithMethod(vault.MethodPost))
		assert.NoError(t, err)
		require.NotNil(t, libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(t, err)
		require.NotNil(t, lib)
		libs[libErrPKI] = lib.GetPublicId()
	}
	{
		libPath := path.Join("database", "creds", "opened")
		opts := []vault.Option{
			vault.WithCredentialType(credential.UserPasswordType),
		}
		libIn, err := vault.NewCredentialLibrary(origStore.GetPublicId(), libPath, opts...)
		assert.NoError(t, err)
		require.NotNil(t, libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(t, err)
		require.NotNil(t, lib)
		libs[libUsrPassDB] = lib.GetPublicId()
	}
	{
		libPath := path.Join("database", "creds", "opened")
		opts := []vault.Option{
			vault.WithCredentialType(credential.UserPasswordType),
			vault.WithMappingOverride(vault.NewUserPasswordOverride(
				vault.WithOverrideUsernameAttribute("test-username"),
				vault.WithOverridePasswordAttribute("test-password"),
			)),
		}
		libIn, err := vault.NewCredentialLibrary(origStore.GetPublicId(), libPath, opts...)
		assert.NoError(t, err)
		require.NotNil(t, libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(t, err)
		require.NotNil(t, lib)
		libs[libErrUsrPassDB] = lib.GetPublicId()
	}
	{
		libPath := path.Join("secret", "data", "my-secret")
		opts := []vault.Option{
			vault.WithCredentialType(credential.UserPasswordType),
		}
		libIn, err := vault.NewCredentialLibrary(origStore.GetPublicId(), libPath, opts...)
		assert.NoError(t, err)
		require.NotNil(t, libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(t, err)
		require.NotNil(t, lib)
		libs[libUsrPassKV] = lib.GetPublicId()
	}
	{
		libPath := path.Join("secret", "data", "fake-secret")
		libIn, err := vault.NewCredentialLibrary(origStore.GetPublicId(), libPath, opts...)
		assert.NoError(t, err)
		require.NotNil(t, libIn)
		lib, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
		assert.NoError(t, err)
		require.NotNil(t, lib)
		libs[libErrKV] = lib.GetPublicId()
	}

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := tcp.TestTarget(context.Background(), t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))

	rc2dc := func(rcs []credential.Request) []*session.DynamicCredential {
		var dcs []*session.DynamicCredential
		for _, rc := range rcs {
			dc := &session.DynamicCredential{
				LibraryId:         rc.SourceId,
				CredentialPurpose: string(rc.Purpose),
			}
			dcs = append(dcs, dc)
		}
		return dcs
	}

	rc2nil := func(rcs []credential.Request) []*session.DynamicCredential { return nil }

	tests := []struct {
		name      string
		convertFn func(rcs []credential.Request) []*session.DynamicCredential
		requests  []credential.Request
		wantErr   errors.Code
	}{
		{
			name:      "one-library-valid",
			convertFn: rc2dc,
			requests: []credential.Request{
				{
					SourceId: libs[libDB],
					Purpose:  credential.ApplicationPurpose,
				},
			},
		},
		{
			name:      "multiple-valid-libraries",
			convertFn: rc2dc,
			requests: []credential.Request{
				{
					SourceId: libs[libDB],
					Purpose:  credential.ApplicationPurpose,
				},
				{
					SourceId: libs[libPKI],
					Purpose:  credential.IngressPurpose,
				},
			},
		},
		{
			name:      "one-library-that-errors",
			convertFn: rc2dc,
			requests: []credential.Request{
				{
					SourceId: libs[libErrPKI],
					Purpose:  credential.IngressPurpose,
				},
			},
			wantErr: errors.VaultCredentialRequest,
		},
		{
			name:      "no-session-dynamic-credentials",
			convertFn: rc2nil,
			requests: []credential.Request{
				{
					SourceId: libs[libDB],
					Purpose:  credential.ApplicationPurpose,
				},
				{
					SourceId: libs[libPKI],
					Purpose:  credential.IngressPurpose,
				},
			},
			wantErr: errors.InvalidDynamicCredential,
		},
		{
			name:      "one-db-valid-username-password-library",
			convertFn: rc2dc,
			requests: []credential.Request{
				{
					SourceId: libs[libUsrPassDB],
					Purpose:  credential.ApplicationPurpose,
				},
			},
		},
		{
			name:      "invalid-username-password-library",
			convertFn: rc2dc,
			requests: []credential.Request{
				{
					SourceId: libs[libErrUsrPassDB],
					Purpose:  credential.ApplicationPurpose,
				},
			},
			wantErr: errors.VaultInvalidCredentialMapping,
		},
		{
			name:      "valid-kv-username-password-library",
			convertFn: rc2dc,
			requests: []credential.Request{
				{
					SourceId: libs[libUsrPassKV],
					Purpose:  credential.ApplicationPurpose,
				},
			},
		},
		{
			name:      "invalid-kv-does-not-exist",
			convertFn: rc2dc,
			requests: []credential.Request{
				{
					SourceId: libs[libErrKV],
					Purpose:  credential.ApplicationPurpose,
				},
			},
			wantErr: errors.VaultEmptySecret,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
				UserId:             uId,
				HostId:             h.GetPublicId(),
				TargetId:           tar.GetPublicId(),
				HostSetId:          hs.GetPublicId(),
				AuthTokenId:        at.GetPublicId(),
				ScopeId:            prj.GetPublicId(),
				Endpoint:           "tcp://127.0.0.1:22",
				DynamicCredentials: tt.convertFn(tt.requests),
			})
			got, err := repo.Issue(ctx, sess.GetPublicId(), tt.requests)
			if tt.wantErr != 0 {
				assert.Truef(errors.Match(errors.T(tt.wantErr), err), "want err: %q got: %q", tt.wantErr, err)
				assert.Nil(got)
				return
			}
			assert.Len(got, len(tt.requests))
			require.NoError(err)
			assert.NotZero(len(got))
			for _, dc := range got {
				switch dc.Library().CredentialType() {
				case credential.UserPasswordType:
					if upc, ok := dc.(credential.UserPassword); ok {
						assert.NotEmpty(upc.Username())
						assert.NotEmpty(upc.Password())
						break
					}
					assert.Fail("want UserPassword credential from library with credential type UserPassword")
				case credential.UnspecifiedType:
					if _, ok := dc.(credential.UserPassword); ok {
						assert.Fail("do not want UserPassword credential from library with credential type Unspecified")
					}
				}
			}
		})
	}
}

func TestRepository_Revoke(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	cs := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	cl := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)[0]

	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := tcp.TestTarget(context.Background(), t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId())

	const (
		sessionCount    = 4
		credentialCount = 4
	)

	sessionIds := make([]string, sessionCount)
	sessions := make(map[string][]*vault.Credential, sessionCount)
	for i := 0; i < sessionCount; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		uId := at.GetIamUserId()

		sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ScopeId:     prj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})
		sessionIds[i] = sess.GetPublicId()
		credentials := vault.TestCredentials(t, conn, wrapper, cl.GetPublicId(), sess.GetPublicId(), credentialCount)
		assert.Len(credentials, credentialCount)
		for _, credential := range credentials {
			assert.NotEmpty(credential.GetPublicId())
		}
		sessions[sess.GetPublicId()] = credentials
	}

	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := vault.NewRepository(rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	ctx := context.Background()
	assert.Error(repo.Revoke(ctx, ""))

	type credCount struct {
		active, revoke            int
		revoked, expired, unknown int
	}

	assertCreds := func(want map[string]*credCount) {
		const query = `
  select session_id, status, count(public_id)
    from credential_vault_credential
group by session_id, status;
`
		got := make(map[string]*credCount, len(want))
		for id := range want {
			got[id] = new(credCount)
		}

		var (
			id     string
			status string
			count  int
		)
		rows, err := rw.Query(ctx, query, nil)
		require.NoError(err)
		defer rows.Close()
		for rows.Next() {
			require.NoError(rows.Scan(&id, &status, &count))
			switch status {
			case "active":
				got[id].active = count
			case "revoke":
				got[id].revoke = count
			case "revoked":
				got[id].revoked = count
			case "expired":
				got[id].expired = count
			case "unknown":
				got[id].unknown = count
			default:
				assert.Failf("Unexpected status: %s", status)
			}
		}
		require.NoError(rows.Err())
		assert.Equal(want, got)
	}

	cc := make(map[string]*credCount, sessionCount)
	for _, id := range sessionIds {
		cc[id] = new(credCount)
		cc[id].active = credentialCount
	}
	for _, id := range sessionIds {
		assert.NoError(repo.Revoke(ctx, id))
		cc[id].revoke = cc[id].active
		cc[id].active = 0
		assertCreds(cc)
	}
}

func Test_TerminateSession(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	cs := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	cl := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)[0]

	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := tcp.TestTarget(context.Background(), t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId())

	const (
		sessionCount    = 4
		credentialCount = 4
	)

	sessionIds := make([]string, sessionCount)
	sessions := make(map[string][]*vault.Credential, sessionCount)
	for i := 0; i < sessionCount; i++ {
		at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
		uId := at.GetIamUserId()

		sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
			UserId:      uId,
			HostId:      h.GetPublicId(),
			TargetId:    tar.GetPublicId(),
			HostSetId:   hs.GetPublicId(),
			AuthTokenId: at.GetPublicId(),
			ScopeId:     prj.GetPublicId(),
			Endpoint:    "tcp://127.0.0.1:22",
		})
		sessionIds[i] = sess.GetPublicId()
		credentials := vault.TestCredentials(t, conn, wrapper, cl.GetPublicId(), sess.GetPublicId(), credentialCount)
		assert.Len(credentials, credentialCount)
		for _, credential := range credentials {
			assert.NotEmpty(credential.GetPublicId())
		}
		sessions[sess.GetPublicId()] = credentials
	}

	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := vault.NewRepository(rw, rw, kms, sche)
	require.NoError(err)
	require.NotNil(repo)

	ctx := context.Background()
	assert.Error(repo.Revoke(ctx, ""))

	type credCount struct {
		active, revoke            int
		revoked, expired, unknown int
	}

	assertCreds := func(want map[string]*credCount) {
		const query = `
  select session_id, status, count(public_id)
    from credential_vault_credential
group by session_id, status;
`
		got := make(map[string]*credCount, len(want))
		for id := range want {
			got[id] = new(credCount)
		}

		var (
			id     string
			status string
			count  int
		)
		rows, err := rw.Query(ctx, query, nil)
		require.NoError(err)
		defer rows.Close()
		for rows.Next() {
			require.NoError(rows.Scan(&id, &status, &count))
			switch status {
			case "active":
				got[id].active = count
			case "revoke":
				got[id].revoke = count
			case "revoked":
				got[id].revoked = count
			case "expired":
				got[id].expired = count
			case "unknown":
				got[id].unknown = count
			default:
				assert.Failf("Unexpected status: %s", status)
			}
		}
		require.NoError(rows.Err())
		assert.Equal(want, got)
	}

	cc := make(map[string]*credCount, sessionCount)
	for _, id := range sessionIds {
		cc[id] = new(credCount)
		cc[id].active = credentialCount
	}

	sessionRepo, err := session.NewRepository(rw, rw, kms)
	require.NoError(err)

	count, err := sessionRepo.TerminateCompletedSessions(ctx)
	assert.NoError(err)
	assert.Zero(count)
	assertCreds(cc)

	// call CancelSession
	id := sessionIds[0]
	_, err = sessionRepo.CancelSession(ctx, id, 1)
	assert.NoError(err)
	cc[id].revoke = cc[id].active
	cc[id].active = 0
	assertCreds(cc)

	count, err = sessionRepo.TerminateCompletedSessions(ctx)
	assert.NoError(err)
	assert.Equal(1, count)
	assertCreds(cc)

	// call TerminateSession
	id = sessionIds[1]
	_, err = sessionRepo.TerminateSession(ctx, id, 1, session.ClosedByUser)
	assert.NoError(err)
	cc[id].revoke = cc[id].active
	cc[id].active = 0
	assertCreds(cc)

	count, err = sessionRepo.TerminateCompletedSessions(ctx)
	assert.NoError(err)
	assert.Zero(count)
	assertCreds(cc)
}
