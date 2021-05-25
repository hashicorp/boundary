package vault

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
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
	sche := scheduler.TestScheduler(t, conn, wrapper)

	repoFn := func() (*Repository, error) { return NewRepository(rw, rw, kmsCache, sche) }

	type args struct {
		repoFn RepositoryFactory
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
			name:        "nil repo fn",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "nil logger",
			args: args{
				repoFn: repoFn,
			},
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid-no-options",
			args: args{
				repoFn: repoFn,
				logger: hclog.L(),
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				repoFn: repoFn,
				logger: hclog.L(),
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := NewTokenRenewalJob(tt.args.repoFn, tt.args.logger, tt.options...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			require.NotNil(got.repoFn)
			require.NotNil(got.logger)
			assert.Equal(tt.wantLimit, got.limit)

			repo, err := got.repoFn()
			require.NoError(err)
			assert.NotNil(repo)
		})
	}
}

func TestTokenRenewal_RunLimits(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	repoFn := func() (*Repository, error) { return NewRepository(rw, rw, kmsCache, sche) }

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

			r, err := NewTokenRenewalJob(repoFn, hclog.L(), tt.opts...)
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

	repoFn := func() (*Repository, error) { return NewRepository(rw, rw, kmsCache, sche) }
	repo, err := repoFn()
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

	r, err := NewTokenRenewalJob(repoFn, hclog.L())
	require.NoError(err)

	err = r.Run(context.Background())
	require.NoError(err)
	// No tokens should have been renewed
	assert.Equal(0, r.numProcessed)

	// Set expiration time in database to 1 minute from now to force token renewal
	count, err := rw.Exec(context.Background(),
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

	repoFn := func() (*Repository, error) { return NewRepository(rw, rw, kmsCache, sche) }
	repo, err := repoFn()
	require.NoError(err)

	cs, err := repo.CreateCredentialStore(context.Background(), in)
	require.NoError(err)

	// Sleep to move clock and expire token
	time.Sleep(time.Second * 2)

	r, err := NewTokenRenewalJob(repoFn, hclog.L())
	require.NoError(err)

	err = r.Run(context.Background())
	require.NoError(err)
	assert.Equal(1, r.numTokens)

	// Verify token was expired in repo
	token := allocToken()
	require.NoError(rw.LookupWhere(context.Background(), &token, "store_id = ?", []interface{}{cs.GetPublicId()}))
	assert.Equal(string(StatusExpired), token.Status)
}

func TestTokenRenewalJob_NextRunIn(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repoFn := func() (*Repository, error) { return NewRepository(rw, rw, kmsCache, sche) }

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs, err := NewCredentialStore(prj.PublicId, "http://vault", []byte("token"))
	assert.NoError(err)
	require.NotNil(cs)
	id, err := newCredentialStoreId()
	assert.NoError(err)
	require.NotEmpty(id)
	cs.PublicId = id
	err = rw.Create(context.Background(), cs)
	require.NoError(err)

	createTokens := func(name string, exp []time.Duration) {
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
			want: defaultTokenRenewalInterval,
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
			r, err := NewTokenRenewalJob(repoFn, hclog.L())
			assert.NoError(err)
			require.NotNil(r)

			createTokens(tt.name, tt.expirations)

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
