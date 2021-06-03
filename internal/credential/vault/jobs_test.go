package vault

import (
	"context"
	"fmt"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/go-hclog"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewTokenRenewalJob(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r      db.Reader
		w      db.Writer
		kms    *kms.Kms
		logger hclog.Logger
	}
	tests := []struct {
		name        string
		args        args
		options     []Option
		wantLimit   int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "nil reader",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil writer",
			args: args{
				r: rw,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil kms",
			args: args{
				r: rw,
				w: rw,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil logger",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			args: args{
				r:      rw,
				w:      rw,
				kms:    kmsCache,
				logger: hclog.L(),
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:      rw,
				w:      rw,
				kms:    kmsCache,
				logger: hclog.L(),
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := NewTokenRenewalJob(tt.args.r, tt.args.w, tt.args.kms, tt.args.logger, tt.options...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.args.r, got.reader)
			assert.Equal(tt.args.w, got.writer)
			assert.Equal(tt.args.kms, got.kms)
			require.NotNil(got.logger)
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestTokenRenewalJob_RunLimits(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	count := 10

	tests := []struct {
		name    string
		opts    []Option
		wantLen int
	}{
		{
			name:    "with-no-limits",
			wantLen: count,
		},
		{
			name:    "with-negative-limit",
			opts:    []Option{WithLimit(-1)},
			wantLen: count,
		},
		{
			name:    "with-limit",
			opts:    []Option{WithLimit(2)},
			wantLen: 2,
		},
		{
			name:    "with-limit-greater-than-count",
			opts:    []Option{WithLimit(count + 5)},
			wantLen: count,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			// Create dummy credential store linked to test vault server to avoid run timing
			// on renew-self network call
			v := NewTestVaultServer(t)
			cs, err := NewCredentialStore(prj.PublicId, v.Addr, []byte("token"))
			assert.NoError(err)
			require.NotNil(cs)
			id, err := newCredentialStoreId()
			assert.NoError(err)
			require.NotEmpty(id)
			cs.PublicId = id
			err = rw.Create(context.Background(), cs)
			require.NoError(err)

			// Create test tokens
			testTokens(t, conn, wrapper, prj.PublicId, cs.PublicId, count)

			r, err := NewTokenRenewalJob(rw, rw, kmsCache, hclog.L(), tt.opts...)
			require.NoError(err)

			err = r.Run(context.Background())
			require.NoError(err)
			assert.Equal(tt.wantLen, r.numTokens)

			// Set all tokens to revoked for next test
			_, err = rw.Exec(context.Background(), "update credential_vault_token set status = 'revoked'", nil)
			assert.NoError(err)
		})
	}
}

func TestTokenRenewalJob_Run(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)

	secret := v.CreateToken(t)
	ct := secret.Auth.ClientToken

	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	assert.NoError(err)
	require.NotNil(in)

	r, err := NewTokenRenewalJob(rw, rw, kmsCache, hclog.L())
	require.NoError(err)

	err = sche.RegisterJob(context.Background(), r)
	require.NoError(err)

	repo, err := NewRepository(rw, rw, kmsCache, sche)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(context.Background(), in)
	require.NoError(err)

	// Sleep to move clock
	time.Sleep(time.Second * 2)

	lookupToken := v.LookupToken(t, ct)
	oldTtl, err := lookupToken.TokenTTL()
	require.NoError(err)

	token := allocToken()
	require.NoError(rw.LookupWhere(context.Background(), &token, "store_id = ?", []interface{}{cs.GetPublicId()}))
	origExp := token.GetExpirationTime().AsTime()

	// Set expiration time in database to 1 hour from now so token should not be up for renewal
	count, err := rw.Exec(context.Background(),
		updateTokenExpirationQuery,
		[]interface{}{int(time.Hour.Seconds()), token.TokenHmac})
	require.NoError(err)
	assert.Equal(1, count)

	err = r.Run(context.Background())
	require.NoError(err)
	// No tokens should have been renewed
	assert.Equal(0, r.numProcessed)

	// Set expiration time in database to 1 minute from now to force token renewal
	count, err = rw.Exec(context.Background(),
		updateTokenExpirationQuery,
		[]interface{}{int(time.Minute.Seconds()), token.TokenHmac})
	require.NoError(err)
	assert.Equal(1, count)

	require.NoError(rw.LookupWhere(context.Background(), &token, "store_id = ?", []interface{}{cs.GetPublicId()}))
	assert.True(token.GetExpirationTime().AsTime().Before(origExp))
	origExp = token.GetExpirationTime().AsTime()

	// Run token renewal again with new expiration time
	err = r.Run(context.Background())
	require.NoError(err)
	// Token should now have been renewed
	assert.Equal(1, r.numProcessed)

	// Verify token was renewed in vault
	lookupToken = v.LookupToken(t, ct)
	newTtl, err := lookupToken.TokenTTL()
	require.NoError(err)
	assert.True(oldTtl < newTtl)

	// Verify token was renewed in repo
	require.NoError(rw.LookupWhere(context.Background(), &token, "store_id = ?", []interface{}{cs.GetPublicId()}))
	assert.True(origExp.Before(token.GetExpirationTime().AsTime()))
}

func TestTokenRenewalJob_RunExpired(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)

	// Create 1s token so it expires in vault
	req := &vault.TokenCreateRequest{
		DisplayName: t.Name(),
		NoParent:    true,
		Period:      "1s",
		Policies:    []string{"default"},
	}
	vc := v.client(t).cl
	ct, err := vc.Auth().Token().Create(req)
	require.NoError(err)
	require.NotNil(ct)

	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct.Auth.ClientToken))
	assert.NoError(err)
	require.NotNil(in)

	r, err := NewTokenRenewalJob(rw, rw, kmsCache, hclog.L())
	require.NoError(err)

	err = sche.RegisterJob(context.Background(), r)
	require.NoError(err)

	repo, err := NewRepository(rw, rw, kmsCache, sche)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(context.Background(), in)
	require.NoError(err)

	// Sleep to move clock and expire token
	time.Sleep(time.Second * 2)

	err = r.Run(context.Background())
	require.NoError(err)
	assert.Equal(1, r.numTokens)

	// Verify token was expired in repo
	token := allocToken()
	require.NoError(rw.LookupWhere(context.Background(), &token, "store_id = ?", []interface{}{cs.GetPublicId()}))
	assert.Equal(string(ExpiredToken), token.Status)
}

func TestTokenRenewalJob_NextRunIn(t *testing.T) {
	t.Parallel()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs, err := NewCredentialStore(prj.PublicId, "http://vault", []byte("token"))
	assert.NoError(t, err)
	require.NotNil(t, cs)
	id, err := newCredentialStoreId()
	assert.NoError(t, err)
	require.NotEmpty(t, id)
	cs.PublicId = id
	err = rw.Create(context.Background(), cs)
	require.NoError(t, err)

	createTokens := func(t *testing.T, name string, exp []time.Duration) {
		t.Helper()
		assert, require := assert.New(t), require.New(t)
		for i, d := range exp {
			databaseWrapper, err := kmsCache.GetWrapper(context.Background(), prj.PublicId, kms.KeyPurposeDatabase)
			token, err := newToken(cs.GetPublicId(), []byte(fmt.Sprintf("%s-token%d", name, i)), []byte(fmt.Sprintf("%s-accessor%d", name, i)), d)
			assert.NoError(err)
			require.NotNil(token)

			require.NoError(token.encrypt(context.Background(), databaseWrapper))

			query := insertTokenQuery
			queryValues := []interface{}{
				token.TokenHmac,
				token.CtToken,
				token.StoreId,
				token.KeyId,
				token.Status,
			}

			expire := int(d.Seconds())
			if expire < 0 {
				// last_renewal_time must be before expiration_time, if we are testing a expiration in the past set
				// lastRenew to 1 second before that
				query = strings.Replace(query,
					"$6, -- last_renewal_time",
					"wt_add_seconds_to_now($6),  -- last_renewal_time",
					-1)
				queryValues = append(queryValues, expire-1, expire)
			} else {
				queryValues = append(queryValues, "now()", expire)
			}

			rows, err := rw.Exec(context.Background(), query, queryValues)
			assert.Equal(1, rows)
			require.NoError(err)
		}
	}

	tests := []struct {
		name        string
		expirations []time.Duration
		want        time.Duration
	}{
		{
			name: "default-duration",
			want: defaultNextRunIn,
		},
		{
			name:        "1-hour-token",
			expirations: []time.Duration{time.Hour},
			want:        30 * time.Minute,
		},
		{
			name:        "2-hour-token",
			expirations: []time.Duration{2 * time.Hour},
			want:        time.Hour,
		},
		{
			name:        "multiple",
			expirations: []time.Duration{24 * time.Hour, 6 * time.Hour, 12 * time.Hour, 10 * time.Hour},
			// 6 hours is the soonest expiration time
			want: 3 * time.Hour,
		},
		{
			name:        "overdue-renewal",
			expirations: []time.Duration{-1 * time.Hour},
			want:        0,
		},
		{
			name:        "multiple-with-single-overdue-renewal",
			expirations: []time.Duration{24 * time.Hour, 6 * time.Hour, -12 * time.Hour, 10 * time.Hour},
			want:        0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r, err := NewTokenRenewalJob(rw, rw, kmsCache, hclog.L())
			assert.NoError(err)
			require.NotNil(r)

			createTokens(t, tt.name, tt.expirations)

			got, err := r.NextRunIn()
			require.NoError(err)
			// Round to time.Minute to account for lost time between creating tokens and determining next run
			assert.Equal(tt.want.Round(time.Minute), got.Round(time.Minute))

			// Set all tokens to revoked for next test
			_, err = rw.Exec(context.Background(), "update credential_vault_token set status = 'revoked'", nil)
			assert.NoError(err)
		})
	}
}

func TestCredentialRenewalJob_Run(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)

	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kmsCache, sche)
	require.NoError(err)

	secret := v.CreateToken(t, WithPolicies([]string{"default", "database"}))
	token := secret.Auth.ClientToken

	credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	require.NoError(err)
	origStore, err := repo.CreateCredentialStore(context.Background(), credStoreIn)
	require.NoError(err)

	libPath := path.Join("database", "creds", "opened")
	libIn, err := NewCredentialLibrary(origStore.GetPublicId(), libPath)
	require.NoError(err)
	libDb, err := repo.CreateCredentialLibrary(context.Background(), prj.GetPublicId(), libIn)
	require.NoError(err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := target.TestTcpTarget(t, conn, prj.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))

	dcs := []*session.DynamicCredential{{
		LibraryId:         libDb.GetPublicId(),
		CredentialPurpose: string(credential.ApplicationPurpose),
	}}

	requests := []credential.Request{{
		SourceId: libDb.GetPublicId(),
		Purpose:  credential.ApplicationPurpose,
	}}

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:             uId,
		HostId:             h.GetPublicId(),
		TargetId:           tar.GetPublicId(),
		HostSetId:          hs.GetPublicId(),
		AuthTokenId:        at.GetPublicId(),
		ScopeId:            prj.GetPublicId(),
		Endpoint:           "tcp://127.0.0.1:22",
		DynamicCredentials: dcs,
	})
	got, err := repo.Issue(context.Background(), sess.GetPublicId(), requests)
	require.NoError(err)
	assert.Len(got, len(requests))

	credRenewal, err := NewCredentialRenewalJob(rw, rw, kmsCache, hclog.L())
	require.NoError(err)

	err = credRenewal.Run(context.Background())
	require.NoError(err)
	// No credentials should have been renewed
	assert.Equal(0, credRenewal.numCreds)

	// Set expiration to 5 minutes from now to force renewal
	cred := allocCredential()
	cred.PublicId = got[0].GetPublicId()
	cred.expiration = 5 * time.Minute
	query, queryValues := cred.updateExpirationQuery()
	count, err := rw.Exec(context.Background(), query, queryValues)
	require.NoError(err)
	assert.Equal(1, count)

	// Lookup to get db expiration time
	err = rw.LookupById(context.Background(), cred)
	require.NoError(err)
	origExpiration := cred.ExpirationTime.AsTime()

	vc := v.client(t)
	secret, err = vc.lookupLease(cred.ExternalId)
	require.NoError(err)
	// Secret should not have a last renewal time
	assert.Nil(secret.Data["last_renewal"])

	// Sleep to move clock
	time.Sleep(2 * time.Second)

	err = credRenewal.Run(context.Background())
	require.NoError(err)
	// The credential should have been renewed
	assert.Equal(1, credRenewal.numCreds)

	// New expiration time should be after origExpiration
	err = rw.LookupById(context.Background(), cred)
	require.NoError(err)
	newExpiration := cred.ExpirationTime.AsTime()
	assert.Truef(newExpiration.After(origExpiration), "expected expiration time to be updated")

	secret, err = vc.lookupLease(cred.ExternalId)
	require.NoError(err)
	// Secret should have a last renewal time
	assert.NotNil(secret.Data["last_renewal"])
}

func TestNewCredentialRenewalJob(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r      db.Reader
		w      db.Writer
		kms    *kms.Kms
		logger hclog.Logger
	}
	tests := []struct {
		name        string
		args        args
		options     []Option
		wantLimit   int
		wantErr     bool
		wantErrCode errors.Code
	}{
		{
			name:        "nil reader",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil writer",
			args: args{
				r: rw,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil kms",
			args: args{
				r: rw,
				w: rw,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil logger",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			args: args{
				r:      rw,
				w:      rw,
				kms:    kmsCache,
				logger: hclog.L(),
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:      rw,
				w:      rw,
				kms:    kmsCache,
				logger: hclog.L(),
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := NewCredentialRenewalJob(tt.args.r, tt.args.w, tt.args.kms, tt.args.logger, tt.options...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.args.r, got.reader)
			assert.Equal(tt.args.w, got.writer)
			assert.Equal(tt.args.kms, got.kms)
			require.NotNil(got.logger)
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestCredentialRenewalJob_RunLimits(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	// Create dummy credential store linked to test vault server to avoid run timing
	// on lease renewal network call
	v := NewTestVaultServer(t)
	cs, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte("token"))
	require.NoError(t, err)
	id, err := newCredentialStoreId()
	require.NoError(t, err)
	cs.PublicId = id
	err = rw.Create(context.Background(), cs)
	require.NoError(t, err)

	testTokens(t, conn, wrapper, prj.PublicId, cs.PublicId, 1)

	cl := TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)[0]

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := target.TestTcpTarget(t, conn, prj.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId())

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	count := 10

	tests := []struct {
		name    string
		opts    []Option
		wantLen int
	}{
		{
			name:    "with-no-limits",
			wantLen: count,
		},
		{
			name:    "with-negative-limit",
			opts:    []Option{WithLimit(-1)},
			wantLen: count,
		},
		{
			name:    "with-limit",
			opts:    []Option{WithLimit(2)},
			wantLen: 2,
		},
		{
			name:    "with-limit-greater-than-count",
			opts:    []Option{WithLimit(count + 5)},
			wantLen: count,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			credentials := TestCredentials(t, conn, wrapper, cl.GetPublicId(), sess.GetPublicId(), count)
			assert.Len(credentials, count)

			r, err := NewCredentialRenewalJob(rw, rw, kmsCache, hclog.L(), tt.opts...)
			require.NoError(err)

			err = r.Run(context.Background())
			require.NoError(err)
			assert.Equal(tt.wantLen, r.numCreds)

			// Set all credential isRenewable to false for next test
			_, err = rw.Exec(context.Background(), "update credential_vault_credential set is_renewable = false", nil)
			assert.NoError(err)
		})
	}
}

func TestCredentialRenewalJob_NextRunIn(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	cl := TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), 1)[0]

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := target.TestTcpTarget(t, conn, prj.GetPublicId(), "test", target.WithHostSets([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId())

	pendingSess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	activeSess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	_ = session.TestState(t, conn, activeSess.PublicId, session.StatusActive)
	cancelingSess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	_ = session.TestState(t, conn, cancelingSess.PublicId, session.StatusActive)
	_ = session.TestState(t, conn, cancelingSess.PublicId, session.StatusCanceling)
	terminatedSess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ScopeId:     prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	_ = session.TestState(t, conn, terminatedSess.PublicId, session.StatusActive)
	_ = session.TestState(t, conn, terminatedSess.PublicId, session.StatusTerminated)

	type args struct {
		expiration time.Duration
		sess       *session.Session
	}
	createCreds := func(t *testing.T, name string, args []args) {
		t.Helper()
		assert, require := assert.New(t), require.New(t)
		for i, arg := range args {
			token := cs.Token()
			id, err := newCredentialId()
			assert.NoError(err)
			require.NotNil(id)

			query := insertCredentialWithExpirationQuery
			queryValues := []interface{}{
				id,
				cl.GetPublicId(),
				arg.sess.GetPublicId(),
				token.GetTokenHmac(),
				fmt.Sprintf("vault/credential/%d", i),
				true,
			}

			expire := int(arg.expiration.Seconds())
			if expire < 0 {
				// last_renewal_time must be before expiration_time, if we are testing a expiration in the past set
				// lastRenew to 1 second before that
				query = strings.Replace(query,
					"$7, -- last_renewal_time",
					"wt_add_seconds_to_now($7),  -- last_renewal_time",
					-1)
				queryValues = append(queryValues, expire-1, expire)
			} else {
				queryValues = append(queryValues, "now()", expire)
			}

			rows, err2 := rw.Exec(context.Background(), query, queryValues)
			assert.Equal(1, rows)
			assert.NoError(err2)
		}
	}

	tests := []struct {
		name string
		args []args
		want time.Duration
	}{
		{
			name: "default-duration",
			want: defaultNextRunIn,
		},
		{
			name: "1-hour-pending-credential",
			args: []args{
				{sess: pendingSess, expiration: time.Hour},
			},
			want: 30 * time.Minute,
		},
		{
			name: "1-hour-active-credential",
			args: []args{
				{sess: activeSess, expiration: time.Hour},
			},
			want: 30 * time.Minute,
		},
		{
			name: "1-hour-cancelling-credential",
			args: []args{
				{sess: cancelingSess, expiration: time.Hour},
			},
			want: defaultNextRunIn,
		},
		{
			name: "1-hour-terminated-credential",
			args: []args{
				{sess: terminatedSess, expiration: time.Hour},
			},
			want: defaultNextRunIn,
		},
		{
			name: "multiple-all-active",
			args: []args{
				{sess: activeSess, expiration: 24 * time.Hour},
				{sess: activeSess, expiration: 6 * time.Hour},
				{sess: activeSess, expiration: 8 * time.Hour},
				{sess: activeSess, expiration: 10 * time.Hour},
			},
			// 6 hours is the soonest expiration time
			want: 3 * time.Hour,
		},
		{
			name: "multiple-all-pending",
			args: []args{
				{sess: pendingSess, expiration: 24 * time.Hour},
				{sess: pendingSess, expiration: 6 * time.Hour},
				{sess: pendingSess, expiration: 8 * time.Hour},
				{sess: pendingSess, expiration: 10 * time.Hour},
			},
			// 6 hours is the soonest expiration time
			want: 3 * time.Hour,
		},
		{
			name: "multiple-mixed-active-pending",
			args: []args{
				{sess: activeSess, expiration: 24 * time.Hour},
				{sess: pendingSess, expiration: 6 * time.Hour},
				{sess: activeSess, expiration: 8 * time.Hour},
				{sess: pendingSess, expiration: 10 * time.Hour},
			},
			// 6 hours is the soonest expiration time
			want: 3 * time.Hour,
		},
		{
			name: "multiple-mixed-active-terminated",
			args: []args{
				{sess: activeSess, expiration: 24 * time.Hour},
				{sess: terminatedSess, expiration: 6 * time.Hour},
				{sess: activeSess, expiration: 8 * time.Hour},
				{sess: terminatedSess, expiration: 10 * time.Hour},
			},
			// 8 hours is the soonest expiration time that is not terminated
			want: 4 * time.Hour,
		},
		{
			name: "multiple-mixed-pending-cancelling",
			args: []args{
				{sess: pendingSess, expiration: 24 * time.Hour},
				{sess: cancelingSess, expiration: 6 * time.Hour},
				{sess: cancelingSess, expiration: 8 * time.Hour},
				{sess: cancelingSess, expiration: 10 * time.Hour},
			},
			// 24 hours is the soonest expiration time that is not cancelling
			want: 12 * time.Hour,
		},
		{
			name: "overdue-active-renewal",
			args: []args{
				{sess: activeSess, expiration: -12 * time.Hour},
			},
			want: 0,
		},
		{
			name: "multiple-active-with-single-active-overdue-renewal",
			args: []args{
				{sess: activeSess, expiration: 24 * time.Hour},
				{sess: activeSess, expiration: 6 * time.Hour},
				{sess: activeSess, expiration: -12 * time.Hour},
				{sess: activeSess, expiration: 10 * time.Hour},
			},
			want: 0,
		},
		{
			name: "multiple-active-with-single-terminated-overdue-renewal",
			args: []args{
				{sess: activeSess, expiration: 24 * time.Hour},
				{sess: activeSess, expiration: 6 * time.Hour},
				{sess: terminatedSess, expiration: -12 * time.Hour},
				{sess: activeSess, expiration: 10 * time.Hour},
			},
			// The overdue terminated session should be ignored
			want: 3 * time.Hour,
		},
		{
			name: "multiple-active-with-single-cancelling-overdue-renewal",
			args: []args{
				{sess: activeSess, expiration: 24 * time.Hour},
				{sess: activeSess, expiration: 6 * time.Hour},
				{sess: cancelingSess, expiration: -12 * time.Hour},
				{sess: activeSess, expiration: 10 * time.Hour},
			},
			// The overdue cancelling session should be ignored
			want: 3 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r, err := NewCredentialRenewalJob(rw, rw, kmsCache, hclog.L())
			assert.NoError(err)
			require.NotNil(r)

			createCreds(t, tt.name, tt.args)

			got, err := r.NextRunIn()
			require.NoError(err)
			// Round to time.Minute to account for lost time between creating credentials and determining next run
			assert.Equal(tt.want.Round(time.Minute), got.Round(time.Minute))

			// Set all credential isRenewable to false for next test
			_, err = rw.Exec(context.Background(), "update credential_vault_credential set is_renewable = false", nil)
			assert.NoError(err)
		})
	}
}
