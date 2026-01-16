// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"database/sql"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/scheduler"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testUpdateTokenStatusExpirationQuery = `
update credential_vault_token
   set status = ?,
       last_renewal_time = now(),
       expiration_time   = wt_add_seconds_to_now(?)
 where token_hmac = ?;
`

func testVaultToken(t *testing.T,
	conn *db.DB,
	wrapper wrapping.Wrapper,
	v *TestVaultServer,
	cs *CredentialStore,
	status TokenStatus,
	expiration time.Duration,
) *Token {
	t.Helper()
	assert, require := assert.New(t), require.New(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	rw := db.New(conn)

	secret, _ := v.CreateToken(t)
	inToken, err := newToken(context.Background(), cs.PublicId, []byte(secret.Auth.ClientToken), []byte(secret.Auth.Accessor), expiration)
	require.NoError(err)
	inToken.Status = string(status)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), cs.ProjectId, kms.KeyPurposeDatabase)
	require.NoError(err)

	require.NoError(inToken.encrypt(context.Background(), databaseWrapper))

	query := insertTokenQuery
	queryValues := []any{
		sql.Named("1", inToken.TokenHmac),
		sql.Named("2", inToken.CtToken),
		sql.Named("3", inToken.StoreId),
		sql.Named("4", inToken.KeyId),
		sql.Named("5", inToken.Status),
	}
	expire := int(expiration.Seconds())
	if expire < 0 {
		// last_renewal_time must be before expiration_time, if we are testing a expiration
		// in the past set last_renewal_time to 1 second before that
		query = strings.Replace(query,
			"@6, -- last_renewal_time",
			"wt_add_seconds_to_now(@6),  -- last_renewal_time",
			-1)
		queryValues = append(queryValues, expire-1, sql.Named("6", expire))
	} else {
		queryValues = append(queryValues, sql.Named("6", "now()"), sql.Named("7", expire))
	}

	numRows, err := rw.Exec(context.Background(), query, queryValues)
	assert.Equal(1, numRows)
	require.NoError(err)

	outToken := allocToken()
	require.NoError(rw.LookupWhere(context.Background(), &outToken, "token_hmac = ?", []any{inToken.TokenHmac}))
	require.NoError(outToken.decrypt(context.Background(), databaseWrapper))

	return outToken
}

func testVaultCred(t *testing.T,
	conn *db.DB,
	v *TestVaultServer,
	cl *CredentialLibrary,
	sess *session.Session,
	token *Token,
	status CredentialStatus,
	expiration time.Duration,
) (*vault.Secret, *Credential) {
	t.Helper()
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)
	rw := db.New(conn)

	client := v.client(t)
	var secret *vault.Secret
	var err error
	switch Method(cl.HttpMethod) {
	case MethodGet:
		secret, err = client.get(ctx, cl.VaultPath)
	case MethodPost:
		secret, err = client.post(ctx, cl.VaultPath, cl.HttpRequestBody)
	}
	require.NoError(err)
	require.NotNil(secret)

	id, err := newCredentialId(ctx)
	require.NoError(err)

	query := insertCredentialWithExpirationQuery
	queryValues := []any{
		sql.Named("public_id", id),
		sql.Named("library_id", cl.GetPublicId()),
		sql.Named("session_id", sess.GetPublicId()),
		sql.Named("token_hmac", token.GetTokenHmac()),
		sql.Named("external_id", secret.LeaseID),
		sql.Named("is_renewable", true),
		sql.Named("status", status),
	}
	expire := int(expiration.Seconds())
	if expire < 0 {
		// last_renewal_time must be before expiration_time, if we are testing a expiration
		// in the past set last_renewal_time to 1 second before that
		query = strings.Replace(query,
			"@last_renewal_time, -- last_renewal_time",
			"wt_add_seconds_to_now(@last_renewal_time),  -- last_renewal_time",
			-1)
		queryValues = append(queryValues, sql.Named("last_renewal_time", expire-1), sql.Named("expiration_time", expire))
	} else {
		queryValues = append(queryValues, sql.Named("last_renewal_time", "now()"), sql.Named("expiration_time", expire))
	}

	numRows, err := rw.Exec(context.Background(), query, queryValues)
	assert.Equal(1, numRows)
	assert.NoError(err)

	outCred := allocCredential()
	require.NoError(rw.LookupWhere(context.Background(), &outCred, "public_id = ?", []any{id}))

	return secret, outCred
}

func TestNewTokenRenewalJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
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
			name: "valid-no-options",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := newTokenRenewalJob(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.options...)
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
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestTokenRenewalJob_RunLimits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	count := 5
	tests := []struct {
		name    string
		opts    []Option
		wantLen int
	}{
		{
			name:    "with-no-limits",
			wantLen: count + 1, // +1 for current token
		},
		{
			name:    "with-negative-limit",
			opts:    []Option{WithLimit(-1)},
			wantLen: count + 1, // +1 for current token
		},
		{
			name:    "with-limit",
			opts:    []Option{WithLimit(2)},
			wantLen: 2,
		},
		{
			name:    "with-limit-greater-than-count",
			opts:    []Option{WithLimit(count + 10)},
			wantLen: count + 1, // +1 for current token
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			_, token := v.CreateToken(t)
			in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
			require.NoError(err)
			repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
			require.NoError(err)
			err = RegisterJobs(ctx, sche, rw, rw, kmsCache)
			require.NoError(err)
			cs, err := repo.CreateCredentialStore(ctx, in)
			require.NoError(err)

			// Create additional tokens and alternative between token statuses, revoked and
			// expired tokens should have no impact on number tokens renewed
			for i := 0; i < count*3; i++ {
				var status TokenStatus
				switch i % 3 {
				case 0:
					status = MaintainingToken
				case 1:
					status = RevokedToken
				case 2:
					status = ExpiredToken
				}
				testVaultToken(t, conn, wrapper, v, cs, status, 5*time.Minute)
			}

			// inserting new tokens moves the current token to a maintaining state, move it back to current and set expiration time
			numRows, err := rw.Exec(ctx, testUpdateTokenStatusExpirationQuery, []any{CurrentToken, time.Minute.Seconds(), cs.outputToken.TokenHmac})
			require.NoError(err)
			assert.Equal(1, numRows)

			r, err := newTokenRenewalJob(ctx, rw, rw, kmsCache, tt.opts...)
			require.NoError(err)

			err = r.Run(ctx, 0)
			require.NoError(err)
			assert.Equal(tt.wantLen, r.numTokens)

			// Set all tokens to revoked for next test
			_, err = rw.Exec(ctx, "update credential_vault_token set status = 'revoked'", nil)
			assert.NoError(err)
		})
	}
}

func TestTokenRenewalJob_Run(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)

	// Create 24 hour token
	_, token := v.CreateToken(t, WithTokenPeriod(24*time.Hour))

	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	require.NoError(err)
	sche := scheduler.TestScheduler(t, conn, wrapper)

	r, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, r)
	require.NoError(err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(err)

	err = r.Run(ctx, 0)
	require.NoError(err)
	// No tokens should have been renewed since token expiration is 24 hours by default
	assert.Equal(0, r.numProcessed)

	// Create maintaining, revoked and expired tokens
	maintainToken := testVaultToken(t, conn, wrapper, v, cs, MaintainingToken, time.Minute)
	revokedToken := testVaultToken(t, conn, wrapper, v, cs, RevokedToken, time.Minute)
	expiredToken := testVaultToken(t, conn, wrapper, v, cs, ExpiredToken, time.Minute)

	// inserting new tokens moves the current token to a maintaining state, move it back to current and set expiration time
	count, err := rw.Exec(ctx, testUpdateTokenStatusExpirationQuery, []any{CurrentToken, time.Minute.Seconds(), cs.outputToken.TokenHmac})
	require.NoError(err)
	assert.Equal(1, count)

	currentToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &currentToken, "token_hmac = ?", []any{cs.outputToken.TokenHmac}))
	databaseWrapper, err := kmsCache.GetWrapper(ctx, cs.ProjectId, kms.KeyPurposeDatabase)
	require.NoError(err)
	require.NoError(currentToken.decrypt(ctx, databaseWrapper))

	// Sleep to move clock
	time.Sleep(time.Second * 2)

	// Get ttls in vault to verify against before running renewal
	lookupToken := v.LookupToken(t, string(currentToken.GetToken()))
	oldCurrentTtl, err := lookupToken.TokenTTL()
	require.NoError(err)
	lookupToken = v.LookupToken(t, string(maintainToken.GetToken()))
	oldMaintainTtl, err := lookupToken.TokenTTL()
	require.NoError(err)
	lookupToken = v.LookupToken(t, string(revokedToken.GetToken()))
	oldRevokedTtl, err := lookupToken.TokenTTL()
	require.NoError(err)
	lookupToken = v.LookupToken(t, string(expiredToken.GetToken()))
	oldExpiredTtl, err := lookupToken.TokenTTL()
	require.NoError(err)

	// Run token renewal again
	err = r.Run(ctx, 0)
	require.NoError(err)
	// Current and maintaining token should have been processed
	assert.Equal(2, r.numProcessed)

	// Verify current and maintaining token were renewed in vault
	lookupToken = v.LookupToken(t, string(currentToken.GetToken()))
	newTtl, err := lookupToken.TokenTTL()
	require.NoError(err)
	assert.True(oldCurrentTtl < newTtl)
	lookupToken = v.LookupToken(t, string(maintainToken.GetToken()))
	newTtl, err = lookupToken.TokenTTL()
	require.NoError(err)
	assert.True(oldMaintainTtl < newTtl)

	// Verify expired and revoked tokens were not renewed in vault
	lookupToken = v.LookupToken(t, string(revokedToken.GetToken()))
	newTtl, err = lookupToken.TokenTTL()
	require.NoError(err)
	assert.True(oldRevokedTtl >= newTtl)
	lookupToken = v.LookupToken(t, string(expiredToken.GetToken()))
	newTtl, err = lookupToken.TokenTTL()
	require.NoError(err)
	assert.True(oldExpiredTtl >= newTtl)

	// Verify current and maintaining tokens were renewed in repo
	repoToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{currentToken.TokenHmac}))
	assert.True(currentToken.GetExpirationTime().AsTime().Before(repoToken.GetExpirationTime().AsTime()))
	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{maintainToken.TokenHmac}))
	assert.True(maintainToken.GetExpirationTime().AsTime().Before(repoToken.GetExpirationTime().AsTime()))

	// Verify revoked and expired tokens were not renewed in the repo
	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{revokedToken.TokenHmac}))
	assert.Equal(revokedToken.GetExpirationTime().AsTime(), repoToken.GetExpirationTime().AsTime())
	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{expiredToken.TokenHmac}))
	assert.Equal(expiredToken.GetExpirationTime().AsTime(), repoToken.GetExpirationTime().AsTime())
}

func TestTokenRenewalJob_RunExpired(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper, scheduler.WithRunJobsInterval(time.Second))
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)

	// Create 2s token so it expires in vault before we can renew it
	_, ct := v.CreateToken(t, WithTokenPeriod(time.Second*2))

	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	assert.NoError(err)
	require.NotNil(in)

	r, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = sche.RegisterJob(ctx, r)
	require.NoError(err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(err)

	// Sleep to move clock and expire token
	time.Sleep(time.Second * 2)

	// Token should have expired in vault, run should now expire in repo
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(1, r.numTokens)

	// Verify token was expired in repo
	token := allocToken()
	require.NoError(rw.LookupWhere(ctx, &token, "store_id = ?", []any{cs.GetPublicId()}))
	assert.Equal(string(ExpiredToken), token.Status)

	// Updating the credential store with a token that will expire before the job scheduler can run should return an error
	_, ct = v.CreateToken(t, WithTokenPeriod(time.Second))
	in, err = NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	assert.NoError(err)
	require.NotNil(in)

	cs, _, err = repo.UpdateCredentialStore(ctx, in, cs.Version+1, []string{"Token"})
	assert.Error(err)
	assert.Nil(cs)

	// Create 1s token so it expires in vault before the job scheduler can run
	_, ct = v.CreateToken(t, WithTokenPeriod(time.Second))
	in, err = NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	assert.NoError(err)
	require.NotNil(in)

	// Should return error because token ttl expires before the run job scheduler interval
	cs, err = repo.CreateCredentialStore(ctx, in)
	require.Error(err)
	require.Nil(cs)
}

// TestTokenRenewalJob_Run_VaultUnreachableTemporarily tests that tokens are not marked
// as expired when Vault is unreachable temporarily.
func TestTokenRenewalJob_Run_VaultUnreachableTemporarily(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper, scheduler.WithRunJobsInterval(time.Second))
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)

	_, ct := v.CreateToken(t, WithTokenPeriod(time.Second*300))
	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	assert.NoError(err)
	require.NotNil(in)

	r, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = sche.RegisterJob(ctx, r)
	require.NoError(err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(err)
	tokenBeforeRenew := allocToken()
	require.NoError(rw.LookupWhere(ctx, &tokenBeforeRenew, "store_id = ?", []any{cs.GetPublicId()}))
	assert.True(time.Now().Before(tokenBeforeRenew.ExpirationTime.AsTime()))
	assert.Equal(string(CurrentToken), tokenBeforeRenew.Status)
	// Shutdown Vault server to make vault unreachable
	v.Shutdown(t)

	// Renewal will fail because Vault is unreachable but job does not return an error
	err = r.Run(ctx, 0)
	require.NoError(err)

	// Verify token was not expired in repo
	tokenAfterFailedRenew := allocToken()
	require.NoError(rw.LookupWhere(ctx, &tokenAfterFailedRenew, "store_id = ?", []any{cs.GetPublicId()}))
	// expiration time is still in the future and token should still be 'current'
	assert.True(time.Now().Before(tokenAfterFailedRenew.ExpirationTime.AsTime()))
	// expiration time should remain the same since renewal failed
	assert.Equal(tokenBeforeRenew.ExpirationTime, tokenAfterFailedRenew.ExpirationTime)
	assert.Equal(string(CurrentToken), tokenAfterFailedRenew.Status)
}

// TestTokenRenewalJob_RunExpired_VaultUnreachable tests token renewal logic when the Vault server becomes unreachable.
// The job should stop attempting to renew the token once the token is expired since the renewal will never
// be successful and there is no guarantee that Vault server will ever be reachable again.
func TestTokenRenewalJob_RunExpired_VaultUnreachablePermanently(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper, scheduler.WithRunJobsInterval(time.Second))
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)

	// Create 2s token so it expires in vault before we can renew it
	_, ct := v.CreateToken(t, WithTokenPeriod(time.Second*2))

	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	assert.NoError(err)
	require.NotNil(in)

	r, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = sche.RegisterJob(ctx, r)
	require.NoError(err)

	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(err)

	tokenBeforeRenew := allocToken()
	require.NoError(rw.LookupWhere(ctx, &tokenBeforeRenew, "store_id = ?", []any{cs.GetPublicId()}))
	// expiration time is in the future
	assert.True(tokenBeforeRenew.ExpirationTime.AsTime().After(time.Now()))
	assert.Equal(string(CurrentToken), tokenBeforeRenew.Status)

	err = r.Run(ctx, 0)
	require.NoError(err)
	tokenAfterSuccessfulRenew := allocToken()
	require.NoError(rw.LookupWhere(ctx, &tokenAfterSuccessfulRenew, "store_id = ?", []any{cs.GetPublicId()}))
	// successful renewal should have updated expiration time
	assert.True(tokenAfterSuccessfulRenew.ExpirationTime.AsTime().After(tokenBeforeRenew.ExpirationTime.AsTime()))
	assert.Equal(string(CurrentToken), tokenAfterSuccessfulRenew.Status)

	// Shutdown Vault server to make vault unreachable
	v.Shutdown(t)
	// Sleep to move clock and expire token
	time.Sleep(time.Second * 2)

	// Renewal should fail, job does not return an error when renewal fails (emits error event)
	err = r.Run(ctx, 0)
	require.NoError(err)

	// token should be marked as expired in the repo since the expiration time has passed
	tokenAfterFailedRenew := allocToken()
	require.NoError(rw.LookupWhere(ctx, &tokenAfterFailedRenew, "store_id = ?", []any{cs.GetPublicId()}))
	assert.Equal(string(ExpiredToken), tokenAfterFailedRenew.Status)
}

func TestTokenRenewalJob_NextRunIn(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	sche := scheduler.TestScheduler(t, conn, wrapper)

	v := NewTestVaultServer(t)

	type tokenArgs struct {
		e time.Duration
		s TokenStatus
	}
	tests := []struct {
		name            string
		currentTokenExp time.Duration
		tokens          []tokenArgs
		want            time.Duration
		skipCredStore   bool
	}{
		{
			name:          "default-duration",
			skipCredStore: true,
			want:          defaultNextRunIn,
		},
		{
			name:            "1-hour-token",
			currentTokenExp: time.Hour,
			want:            30 * time.Minute,
		},
		{
			name:            "2-hour-token",
			currentTokenExp: 2 * time.Hour,
			want:            time.Hour,
		},
		{
			name:            "multiple-maintaining",
			currentTokenExp: 24 * time.Hour,
			tokens: []tokenArgs{
				{e: 12 * time.Hour, s: MaintainingToken},
				{e: 6 * time.Hour, s: MaintainingToken},
				{e: 8 * time.Hour, s: MaintainingToken},
			},
			// 6 hours is the soonest expiry
			want: 3 * time.Hour,
		},
		{
			name:            "multiple-maintaining-with-single-overdue-renewal",
			currentTokenExp: 24 * time.Hour,
			tokens: []tokenArgs{
				{e: 24 * time.Hour, s: MaintainingToken},
				{e: 6 * time.Hour, s: MaintainingToken},
				{e: -12 * time.Hour, s: MaintainingToken},
				{e: 10 * time.Hour, s: MaintainingToken},
			},
			want: 0,
		},
		{
			name:            "multiple-current-soonest",
			currentTokenExp: 6 * time.Hour,
			tokens: []tokenArgs{
				{e: time.Minute, s: RevokedToken},
				{e: time.Minute, s: ExpiredToken},
				{e: 8 * time.Hour, s: MaintainingToken},
			},
			// 6 hours is the soonest expiry, revoked and expired tokens with sooner
			// expirations should be ignored
			want: 3 * time.Hour,
		},
		{
			name:            "multiple-maintaining-soonest",
			currentTokenExp: 6 * time.Hour,
			tokens: []tokenArgs{
				{e: time.Minute, s: RevokedToken},
				{e: time.Minute, s: ExpiredToken},
				{e: 4 * time.Hour, s: MaintainingToken},
			},
			// 4 hour maintaining token is the soonest expiry
			// revoked and expired tokens with sooner expirations should be ignored
			want: 2 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(r)

			if !tt.skipCredStore {
				_, token := v.CreateToken(t)
				in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
				require.NoError(err)
				repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
				require.NoError(err)
				err = RegisterJobs(ctx, sche, rw, rw, kmsCache)
				require.NoError(err)
				cs, err := repo.CreateCredentialStore(ctx, in)
				require.NoError(err)

				for _, token := range tt.tokens {
					testVaultToken(t, conn, wrapper, v, cs, token.s, token.e)
				}

				// inserting new tokens moves the current token to a maintaining state, move it back to current and set expiration time
				count, err := rw.Exec(ctx, testUpdateTokenStatusExpirationQuery, []any{CurrentToken, tt.currentTokenExp.Seconds(), cs.outputToken.TokenHmac})
				require.NoError(err)
				assert.Equal(1, count)
			}

			got, err := r.NextRunIn(ctx)
			require.NoError(err)
			// Round to time.Minute to account for lost time between creating tokens and determining next run
			assert.Equal(tt.want.Round(time.Minute), got.Round(time.Minute))

			// Set all tokens to revoked for next test
			_, err = rw.Exec(ctx, "update credential_vault_token set status = 'revoked'", nil)
			assert.NoError(err)
		})
	}
}

func TestNewTokenRevocationJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
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
			name: "valid-no-options",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := newTokenRevocationJob(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.options...)
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
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestTokenRevocationJob_RunLimits(t *testing.T) {
	ctx := context.Background()

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	sche := scheduler.TestScheduler(t, conn, wrapper)

	v := NewTestVaultServer(t)

	count := 5
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

			_, token := v.CreateToken(t)
			in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
			require.NoError(err)
			repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
			require.NoError(err)
			err = RegisterJobs(ctx, sche, rw, rw, kmsCache)
			require.NoError(err)

			cs, err := repo.CreateCredentialStore(ctx, in)
			require.NoError(err)

			for i := 0; i < count*3; i++ {
				var status TokenStatus
				// Alternative between token status, the current token as well as the
				// revoked and expired tokens should have no impact on number tokens revoked
				switch i % 3 {
				case 0:
					status = MaintainingToken
				case 1:
					status = RevokedToken
				case 2:
					status = ExpiredToken
				}
				testVaultToken(t, conn, wrapper, v, cs, status, 5*time.Minute)
			}

			// inserting new tokens moves the current token to a maintaining state, move it back to current and set expiration time
			numRows, err := rw.Exec(ctx, testUpdateTokenStatusExpirationQuery, []any{CurrentToken, time.Minute.Seconds(), cs.outputToken.TokenHmac})
			require.NoError(err)
			assert.Equal(1, numRows)

			r, err := newTokenRevocationJob(ctx, rw, rw, kmsCache, tt.opts...)
			require.NoError(err)

			err = r.Run(ctx, 0)
			require.NoError(err)
			assert.Equal(tt.wantLen, r.numTokens)

			// Set all tokens to revoked for next test
			_, err = rw.Exec(ctx, "update credential_vault_token set status = 'revoked'", nil)
			require.NoError(err)
		})
	}
}

func TestTokenRevocationJob_Run(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	_, ct := v.CreateToken(t)
	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	require.NoError(err)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)

	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(err)

	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(err)

	r, err := newTokenRevocationJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = sche.RegisterJob(ctx, r)
	require.NoError(err)

	// No tokens should have been revoked since only the current token exists
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(0, r.numProcessed)

	// Create maintaining tokens with and without credentials
	noCredsToken := testVaultToken(t, conn, wrapper, v, cs, MaintainingToken, 5*time.Minute)
	credsToken := testVaultToken(t, conn, wrapper, v, cs, MaintainingToken, 5*time.Minute)
	revokeToken := testVaultToken(t, conn, wrapper, v, cs, RevokeToken, 5*time.Minute)

	// inserting new tokens moves the current token to a maintaining state, move it back to current and set expiration time
	count, err := rw.Exec(ctx, testUpdateTokenStatusExpirationQuery, []any{CurrentToken, (5 * time.Minute).Seconds(), cs.outputToken.TokenHmac})
	require.NoError(err)
	assert.Equal(1, count)

	// Create cred lib and session for credential
	libPath := path.Join("database", "creds", "opened")
	cl, err := NewCredentialLibrary(cs.PublicId, libPath, WithMethod(MethodGet))
	require.NoError(err)
	cl.PublicId, err = newCredentialLibraryId(ctx)
	require.NoError(err)
	err = rw.Create(ctx, cl)
	require.NoError(err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId(), string(cl.CredentialType()))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	// Create credential attached to credsToken
	_, cred := testVaultCred(t, conn, v, cl, sess, credsToken, ActiveCredential, 5*time.Minute)

	// Create fake credential attached to revokeToken
	_, revokeCred := testVaultCred(t, conn, v, cl, sess, revokeToken, ActiveCredential, 5*time.Minute)

	// Running should revoke noCredsToken and the revokeToken even though it has active
	// credentials it has been marked for revocation
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(2, r.numProcessed)

	// Verify noCredsToken was revoked in vault
	v.VerifyTokenInvalid(t, string(noCredsToken.GetToken()))

	// Verify noCredsToken was set to revoked in repo
	repoToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{noCredsToken.TokenHmac}))
	assert.Equal(string(RevokedToken), repoToken.Status)

	// Verify revokeToken was revoked in vault
	v.VerifyTokenInvalid(t, string(revokeToken.GetToken()))

	// Verify revokeToken was set to revoked in repo
	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{revokeToken.TokenHmac}))
	assert.Equal(string(RevokedToken), repoToken.Status)

	// Verify revokeCred attached to revokeToken were marked as revoked
	lookupCred := allocCredential()
	lookupCred.PublicId = revokeCred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(RevokedCredential), lookupCred.Status)

	// Verify credsToken was not revoked in vault
	lookupToken := v.LookupToken(t, string(credsToken.GetToken()))
	assert.NotNil(lookupToken)

	// Revoke credential in repo
	query, queryValues := cred.updateStatusQuery(RevokedCredential)
	rows, err := rw.Exec(ctx, query, queryValues)
	assert.Equal(1, rows)
	assert.NoError(err)

	// Running again should now revoke the credsToken
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(1, r.numProcessed)

	// Verify credsToken was revoked in vault
	v.VerifyTokenInvalid(t, string(credsToken.GetToken()))

	// Verify credsToken was set to revoked in repo
	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{credsToken.TokenHmac}))
	assert.Equal(string(RevokedToken), repoToken.Status)

	err = r.Run(ctx, 0)
	require.NoError(err)
	// With only the current token remaining no tokens should be revoked
	assert.Equal(0, r.numProcessed)
}

func TestNewCredentialRenewalJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
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
			name: "valid-no-options",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := newCredentialRenewalJob(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.options...)
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
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestCredentialRenewalJob_RunLimits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)
	_, ct := v.CreateToken(t)
	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	require.NoError(t, err)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(t, err)

	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(t, err)

	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(t, err)

	libPath := path.Join("database", "creds", "opened")
	cl, err := NewCredentialLibrary(cs.PublicId, libPath, WithMethod(MethodGet))
	require.NoError(t, err)
	cl.PublicId, err = newCredentialLibraryId(ctx)
	require.NoError(t, err)
	err = rw.Create(ctx, cl)
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId(), string(cl.CredentialType()))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	credsToken := testVaultToken(t, conn, wrapper, v, cs, CurrentToken, 5*time.Minute)

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

			for i := 0; i < count*4; i++ {
				var status CredentialStatus
				// Alternative between cred status, revoke, revoked and expired should have
				// no impact on number creds renewed.  Only active creds should be renewed
				switch i % 4 {
				case 0:
					status = ActiveCredential
				case 1:
					status = RevokeCredential
				case 2:
					status = RevokedCredential
				case 3:
					status = ExpiredCredential
				}
				testVaultCred(t, conn, v, cl, sess, credsToken, status, 5*time.Minute)
			}

			r, err := newCredentialRenewalJob(ctx, rw, rw, kmsCache, tt.opts...)
			require.NoError(err)

			err = r.Run(ctx, 0)
			require.NoError(err)
			assert.Equal(tt.wantLen, r.numCreds)

			// Set all credentials to revoked for next test
			_, err = rw.Exec(ctx, "update credential_vault_credential set status = 'revoked'", nil)
			assert.NoError(err)
		})
	}
}

func TestCredentialRenewalJob_Run(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)

	_, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "database"}))
	credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	require.NoError(err)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, credStoreIn)
	require.NoError(err)

	libPath := path.Join("database", "creds", "opened")
	libIn, err := NewCredentialLibrary(cs.GetPublicId(), libPath)
	require.NoError(err)
	cl, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
	require.NoError(err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(context.Background(), t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	csToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &csToken, "token_hmac = ?", []any{cs.outputToken.TokenHmac}))

	credRenewal, err := newCredentialRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = credRenewal.Run(ctx, 0)
	require.NoError(err)
	// No credentials should have been renewed
	assert.Equal(0, credRenewal.numCreds)

	_, activeCred := testVaultCred(t, conn, v, cl, sess, csToken, ActiveCredential, 5*time.Minute)
	_, revokeCred := testVaultCred(t, conn, v, cl, sess, csToken, RevokeCredential, 5*time.Minute)
	_, revokedCred := testVaultCred(t, conn, v, cl, sess, csToken, RevokedCredential, 5*time.Minute)
	_, expiredCred := testVaultCred(t, conn, v, cl, sess, csToken, ExpiredCredential, 5*time.Minute)

	secret := v.LookupLease(t, activeCred.ExternalId)
	// Secret should not have a last renewal time
	assert.Nil(secret.Data["last_renewal"])

	// Sleep to move clock
	time.Sleep(2 * time.Second)

	err = credRenewal.Run(ctx, 0)
	require.NoError(err)
	// The active credential should have been renewed
	assert.Equal(1, credRenewal.numCreds)

	// Active credential expiration time should have been updated
	lookupCred := allocCredential()
	lookupCred.PublicId = activeCred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Truef(lookupCred.ExpirationTime.AsTime().After(activeCred.ExpirationTime.AsTime()), "expected expiration time to be updated")

	// Revoke, Revoked and Expired credentials expiration times should not have changed
	lookupCred = allocCredential()
	lookupCred.PublicId = revokeCred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(lookupCred.ExpirationTime.AsTime(), revokeCred.ExpirationTime.AsTime())
	lookupCred = allocCredential()
	lookupCred.PublicId = revokedCred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(lookupCred.ExpirationTime.AsTime(), revokedCred.ExpirationTime.AsTime())
	lookupCred = allocCredential()
	lookupCred.PublicId = expiredCred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(lookupCred.ExpirationTime.AsTime(), expiredCred.ExpirationTime.AsTime())

	// Active credential should have a last renewal time in Vault
	secret = v.LookupLease(t, activeCred.ExternalId)
	assert.NotNil(secret.Data["last_renewal"])

	// Revoke, Revoked and Expired credentials should not have a last renewal time
	secret = v.LookupLease(t, revokeCred.ExternalId)
	assert.Nil(secret.Data["last_renewal"])
	secret = v.LookupLease(t, revokedCred.ExternalId)
	assert.Nil(secret.Data["last_renewal"])
	secret = v.LookupLease(t, expiredCred.ExternalId)
	assert.Nil(secret.Data["last_renewal"])
}

func TestCredentialRenewalJob_RunExpired(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)

	_, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "database"}))
	credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	require.NoError(err)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, credStoreIn)
	require.NoError(err)

	libPath := path.Join("database", "creds", "opened")
	libIn, err := NewCredentialLibrary(cs.GetPublicId(), libPath)
	require.NoError(err)
	cl, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
	require.NoError(err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	repoToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs.outputToken.TokenHmac}))

	credRenewal, err := newCredentialRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	_, cred := testVaultCred(t, conn, v, cl, sess, repoToken, ActiveCredential, time.Minute)

	vc := v.client(t).cl
	// revoke the credential in Vault outside of the job
	assert.NoError(vc.Sys().Revoke(cred.ExternalId))

	// Credential status should still be active
	lookupCred := allocCredential()
	lookupCred.PublicId = cred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(ActiveCredential), lookupCred.Status)

	err = credRenewal.Run(ctx, 0)
	require.NoError(err)
	// The active credential should have been processed
	assert.Equal(1, credRenewal.numCreds)

	// Credential status should have been updated to expired
	lookupCred = allocCredential()
	lookupCred.PublicId = cred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(ExpiredCredential), lookupCred.Status)
}

func TestCredentialRenewalJob_NextRunIn(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	_, ct := v.CreateToken(t)
	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	require.NoError(t, err)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(t, err)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(t, err)
	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(t, err)

	libPath := path.Join("database", "creds", "opened")
	libIn, err := NewCredentialLibrary(cs.GetPublicId(), libPath)
	require.NoError(t, err)
	cl, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId(), string(cl.CredentialType()))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	type args struct {
		e time.Duration
		s CredentialStatus
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
			name: "1-hour-active-credential",
			args: []args{
				{s: ActiveCredential, e: time.Hour},
			},
			want: 30 * time.Minute,
		},
		{
			name: "1-hour-revoke-credential",
			args: []args{
				{s: RevokeCredential, e: time.Hour},
			},
			want: defaultNextRunIn,
		},
		{
			name: "1-hour-revoked-credential",
			args: []args{
				{s: RevokedCredential, e: time.Hour},
			},
			want: defaultNextRunIn,
		},
		{
			name: "1-hour-expired-credential",
			args: []args{
				{s: ExpiredCredential, e: time.Hour},
			},
			want: defaultNextRunIn,
		},
		{
			name: "multiple-all-active",
			args: []args{
				{s: ActiveCredential, e: 24 * time.Hour},
				{s: ActiveCredential, e: 6 * time.Hour},
				{s: ActiveCredential, e: 10 * time.Hour},
			},
			// 6 hours is the soonest expiration time
			want: 3 * time.Hour,
		},
		{
			name: "multiple-mixed",
			args: []args{
				{s: RevokeCredential, e: 2 * time.Hour},
				{s: ActiveCredential, e: 48 * time.Hour},
				{s: ActiveCredential, e: 24 * time.Hour},
				{s: RevokedCredential, e: 6 * time.Hour},
				{s: RevokeCredential, e: 8 * time.Hour},
				{s: ExpiredCredential, e: 10 * time.Hour},
			},
			// 24 hours is the soonest active expiration time
			want: 12 * time.Hour,
		},
		{
			name: "overdue-active-renewal",
			args: []args{
				{s: ActiveCredential, e: -12 * time.Hour},
			},
			want: 0,
		},
		{
			name: "non-active-overdue",
			args: []args{
				{s: ActiveCredential, e: 24 * time.Hour},
				{s: ExpiredCredential, e: -12 * time.Hour},
				{s: RevokeCredential, e: -12 * time.Hour},
				{s: RevokedCredential, e: -12 * time.Hour},
			},
			// The active credential is expiring in 24 hours the non active credentials
			// that are overdue should not impact the query
			want: 12 * time.Hour,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			r, err := newCredentialRenewalJob(ctx, rw, rw, kmsCache)
			assert.NoError(err)
			require.NotNil(r)

			token := testVaultToken(t, conn, wrapper, v, cs, CurrentToken, 5*time.Minute)
			for _, cred := range tt.args {
				testVaultCred(t, conn, v, cl, sess, token, cred.s, cred.e)
			}

			got, err := r.NextRunIn(ctx)
			require.NoError(err)
			// Round to time.Minute to account for lost time between creating credentials and determining next run
			assert.Equal(tt.want.Round(time.Minute), got.Round(time.Minute))

			// Set all credentials to revoked for next test
			_, err = rw.Exec(ctx, "update credential_vault_credential set status = 'revoked'", nil)
			assert.NoError(err)
		})
	}
}

func TestNewCredentialRevocationJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
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
			name: "valid-no-options",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := newCredentialRevocationJob(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.options...)
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
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestCredentialRevocationJob_RunLimits(t *testing.T) {
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)
	_, ct := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "database"}))
	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	require.NoError(t, err)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(t, err)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(t, err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(t, err)
	cs, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(t, err)

	libPath := path.Join("database", "creds", "opened")
	cl, err := NewCredentialLibrary(cs.PublicId, libPath, WithMethod(MethodGet))
	require.NoError(t, err)
	cl.PublicId, err = newCredentialLibraryId(ctx)
	require.NoError(t, err)
	err = rw.Create(ctx, cl)
	require.NoError(t, err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId(), string(cl.CredentialType()))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	repoToken := allocToken()
	require.NoError(t, rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs.outputToken.TokenHmac}))

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

			for i := 0; i < count*4; i++ {
				var status CredentialStatus
				// Alternative between cred status, active, revoked and expired should have
				// no impact on number creds revoked.  Only revoke creds should be revoked.
				switch i % 4 {
				case 0:
					status = ActiveCredential
				case 1:
					status = RevokeCredential
				case 2:
					status = RevokedCredential
				case 3:
					status = ExpiredCredential
				}
				testVaultCred(t, conn, v, cl, sess, repoToken, status, 5*time.Minute)
			}

			r, err := newCredentialRevocationJob(ctx, rw, rw, kmsCache, tt.opts...)
			require.NoError(err)

			err = r.Run(ctx, 0)
			require.NoError(err)
			assert.Equal(tt.wantLen, r.numCreds)

			// Set all credentials to revoked for next test
			_, err = rw.Exec(ctx, "update credential_vault_credential set status = 'revoked'", nil)
			assert.NoError(err)
		})
	}
}

func TestCredentialRevocationJob_Run(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	testDb := v.MountDatabase(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)

	_, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "database"}))
	credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	require.NoError(err)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, credStoreIn)
	require.NoError(err)

	libPath := path.Join("database", "creds", "opened")
	libIn, err := NewCredentialLibrary(cs.GetPublicId(), libPath)
	require.NoError(err)
	cl, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
	require.NoError(err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	repoToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs.outputToken.TokenHmac}))

	r, err := newCredentialRevocationJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = r.Run(ctx, 0)
	require.NoError(err)
	// No credentials should have been revoked
	assert.Equal(0, r.numCreds)

	secret1, _ := testVaultCred(t, conn, v, cl, sess, repoToken, ActiveCredential, 5*time.Minute)
	revokeSecret, revokeCred := testVaultCred(t, conn, v, cl, sess, repoToken, RevokeCredential, 5*time.Minute)
	secret2, _ := testVaultCred(t, conn, v, cl, sess, repoToken, RevokedCredential, 5*time.Minute)
	secret3, _ := testVaultCred(t, conn, v, cl, sess, repoToken, ExpiredCredential, 5*time.Minute)

	// Verify the revokeCred has a status of revoke
	lookupCred := allocCredential()
	lookupCred.PublicId = revokeCred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(RevokeCredential), lookupCred.Status)

	// Verify revokeCred is valid in testDb
	assert.NoError(testDb.ValidateCredential(t, revokeSecret))

	err = r.Run(ctx, 0)
	require.NoError(err)
	// The revoke credential should have been revoked
	assert.Equal(1, r.numCreds)

	// revokeCred should now have a status of revoked
	lookupCred = allocCredential()
	lookupCred.PublicId = revokeCred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(RevokedCredential), lookupCred.Status)

	// revokeCred should no longer be valid in test database
	assert.Error(testDb.ValidateCredential(t, revokeSecret))

	// Other creds should still be valid in test database
	assert.NoError(testDb.ValidateCredential(t, secret1))
	assert.NoError(testDb.ValidateCredential(t, secret2))
	assert.NoError(testDb.ValidateCredential(t, secret3))
}

func TestCredentialRevocationJob_RunDeleted(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	testDb := v.MountDatabase(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)

	_, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "database"}))
	credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	require.NoError(err)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, credStoreIn)
	require.NoError(err)

	libPath := path.Join("database", "creds", "opened")
	libIn, err := NewCredentialLibrary(cs.GetPublicId(), libPath)
	require.NoError(err)
	cl, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
	require.NoError(err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	repoToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs.outputToken.TokenHmac}))

	r, err := newCredentialRevocationJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	secret, cred := testVaultCred(t, conn, v, cl, sess, repoToken, ActiveCredential, 5*time.Hour)

	err = r.Run(ctx, 0)
	require.NoError(err)
	// No credentials should have been revoked as expiration is 5 hours from now
	assert.Equal(0, r.numCreds)

	// Deleting the library should set the cred library_id to null, but not revoke the cred
	count, err := rw.Delete(ctx, cl)
	require.NoError(err)
	assert.Equal(1, count)

	err = r.Run(ctx, 0)
	require.NoError(err)
	// No credentials should have been revoked
	assert.Equal(0, r.numCreds)

	// Verify the cred has a status of active with an empty libraryId
	lookupCred := allocCredential()
	lookupCred.PublicId = cred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(ActiveCredential), lookupCred.Status)
	assert.Empty(lookupCred.LibraryId)

	// secret should still be valid in test database
	assert.NoError(testDb.ValidateCredential(t, secret))

	// Deleting the session should set the cred session_id to null and schedule cred for revocation
	count, err = rw.Delete(ctx, sess)
	require.NoError(err)
	assert.Equal(1, count)

	// cred should now have a status of revoke and empty sessionId
	lookupCred = allocCredential()
	lookupCred.PublicId = cred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Empty(lookupCred.SessionId)
	assert.Equal(string(RevokeCredential), lookupCred.Status)

	err = r.Run(ctx, 0)
	require.NoError(err)
	// The revoke credential should have been revoked
	assert.Equal(1, r.numCreds)

	// cred should now have a status of revoked
	lookupCred = allocCredential()
	lookupCred.PublicId = cred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(RevokedCredential), lookupCred.Status)

	// secret should no longer be valid in test database
	assert.Error(testDb.ValidateCredential(t, secret))
}

func TestNewCredentialStoreCleanupJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	type args struct {
		r   db.Reader
		w   db.Writer
		kms *kms.Kms
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
			name: "valid-no-options",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			wantLimit: db.DefaultLimit,
		},
		{
			name: "valid-with-limit",
			args: args{
				r:   rw,
				w:   rw,
				kms: kmsCache,
			},
			options:   []Option{WithLimit(100)},
			wantLimit: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := newCredentialStoreCleanupJob(context.Background(), tt.args.r, tt.args.w, tt.args.kms, tt.options...)
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
			assert.Equal(tt.wantLimit, got.limit)
		})
	}
}

func TestCredentialStoreCleanupJob_Run(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	v := NewTestVaultServer(t)

	_, ct := v.CreateToken(t)
	in, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	require.NoError(err)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(context.Background(), j)
	require.NoError(err)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)
	cs1, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(err)

	_, ct = v.CreateToken(t)
	in, err = NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(ct))
	require.NoError(err)
	cs2, err := repo.CreateCredentialStore(ctx, in)
	require.NoError(err)

	// Get token hmac for verifications below
	repoToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "store_id = ?", []any{cs1.PublicId}))
	cs1TokenHmac := repoToken.TokenHmac

	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "store_id = ?", []any{cs2.PublicId}))
	cs2TokenHmac := repoToken.TokenHmac

	// create second token on cs2
	secondToken := testVaultToken(t, conn, wrapper, v, cs2, MaintainingToken, time.Hour)

	r, err := newCredentialStoreCleanupJob(ctx, rw, rw, kmsCache)
	require.NoError(err)

	err = sche.RegisterJob(ctx, r)
	require.NoError(err)

	// No credential stores should have been cleaned up
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(0, r.numStores)

	// Register token revocation job needed for delete
	j1, err := newTokenRevocationJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, j1)
	require.NoError(err)

	// Soft delete both credential stores
	count, err := repo.DeleteCredentialStore(ctx, cs1.PublicId)
	require.NoError(err)
	assert.Equal(1, count)

	count, err = repo.DeleteCredentialStore(ctx, cs2.PublicId)
	require.NoError(err)
	assert.Equal(1, count)

	// Verify tokens have been set to revoke
	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "store_id = ?", []any{cs1.PublicId}))
	assert.Equal(string(RevokeToken), repoToken.Status)

	repoToken = allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "store_id = ?", []any{cs2.PublicId}))
	assert.Equal(string(RevokeToken), repoToken.Status)

	// Both soft deleted credential stores should not be cleaned up yet
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(0, r.numStores)

	// Update cs1 token to be marked as revoked
	count, err = rw.Exec(ctx, updateTokenStatusQuery, []any{RevokedToken, cs1TokenHmac})
	require.NoError(err)
	assert.Equal(1, count)

	// cs1 should be deleted
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(1, r.numStores)

	// Lookup of cs1 and its token should fail
	agg := allocListLookupStore()
	agg.PublicId = cs1.PublicId
	err = rw.LookupByPublicId(ctx, agg)
	require.Error(err)
	assert.True(errors.IsNotFoundError(err))
	repoToken = allocToken()
	err = rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs1TokenHmac})
	require.Error(err)
	assert.True(errors.IsNotFoundError(err))

	// Lookup of cs2 and its token should not error
	_, err = repo.LookupCredentialStore(ctx, cs2.PublicId)
	require.NoError(err)
	repoToken = allocToken()
	err = rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs2TokenHmac})
	require.NoError(err)

	// Update cs2 token expiration time
	count, err = rw.Exec(ctx, "update credential_vault_token set expiration_time = now() where token_hmac = ?;", []any{cs2TokenHmac})
	require.NoError(err)
	assert.Equal(1, count)

	// cs2 still has a second token not yet revoked/expired
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(0, r.numStores)

	// Lookup of cs2 and its token should not error
	_, err = repo.LookupCredentialStore(ctx, cs2.PublicId)
	require.NoError(err)
	repoToken = allocToken()
	err = rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs2TokenHmac})
	require.NoError(err)

	// set secondToken with an expired status
	count, err = rw.Exec(ctx, updateTokenStatusQuery, []any{ExpiredToken, secondToken.TokenHmac})
	require.NoError(err)
	assert.Equal(1, count)

	// With no un-expired or un-revoked tokens cs2 should now be deleted
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(1, r.numStores)

	// Lookup of cs2 and its token should fail
	agg = allocListLookupStore()
	agg.PublicId = cs2.PublicId
	err = rw.LookupByPublicId(ctx, agg)
	require.Error(err)
	assert.True(errors.IsNotFoundError(err))
	repoToken = allocToken()
	err = rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs2TokenHmac})
	require.Error(err)
	assert.True(errors.IsNotFoundError(err))
	err = rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{secondToken.TokenHmac})
	require.Error(err)
	assert.True(errors.IsNotFoundError(err))
}

func TestNewCredentialCleanupJob(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)

	type args struct {
		w db.Writer
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
			name:        "nil writer",
			wantErr:     true,
			wantErrCode: errors.InvalidParameter,
		},
		{
			name: "valid",
			args: args{
				w: rw,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			got, err := newCredentialCleanupJob(context.Background(), tt.args.w)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				assert.Truef(errors.Match(errors.T(tt.wantErrCode), err), "Unexpected error %s", err)
				return
			}
			require.NoError(err)
			require.NotNil(got)
			assert.Equal(tt.args.w, got.writer)
		})
	}
}

func TestVaultJobsCorrelationId(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId, "http://vault", "vault-token", "accessor")
	lib := TestCredentialLibraries(t, conn, wrapper, cs.PublicId, globals.UnspecifiedCredentialType, 1)[0]
	token := cs.Token()

	iamRepo := iam.TestRepo(t, conn, wrapper)

	// Create session with known correlationId
	corId, err := uuid.GenerateUUID()
	require.NoError(err)

	composedOf := session.TestSessionParams(t, conn, wrapper, iamRepo)
	composedOf.CorrelationId = corId

	sess := session.TestSession(t, conn, wrapper, composedOf)
	got, err := newCredential(ctx, lib.GetPublicId(), "some/vault/credential", token.GetTokenHmac(), time.Minute)
	require.NoError(err)
	id, err := newCredentialId(ctx)
	assert.NoError(err)
	got.PublicId = id
	query, queryValues := insertQuery(got, sess.PublicId)
	require.NoError(err)
	rows, err := rw.Exec(ctx, query, queryValues)
	assert.Equal(1, rows)
	assert.NoError(err)

	cred := &privateCredential{PublicId: id}
	err = rw.LookupById(ctx, cred)
	require.NoError(err)
	require.NotEmpty(cred.SessionCorrelationId)
	assert.Equal(corId, cred.SessionCorrelationId)
}

func TestCredentialCleanupJob_Run(t *testing.T) {
	ctx := context.Background()
	assert, require := assert.New(t), require.New(t)

	v := NewTestVaultServer(t, WithDockerNetwork(true))
	v.MountDatabase(t)

	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	kmsCache := kms.TestKms(t, conn, wrapper)
	sche := scheduler.TestScheduler(t, conn, wrapper)
	repo, err := NewRepository(ctx, rw, rw, kmsCache, sche)
	require.NoError(err)

	_, token := v.CreateToken(t, WithPolicies([]string{"default", "boundary-controller", "database"}))
	credStoreIn, err := NewCredentialStore(prj.GetPublicId(), v.Addr, []byte(token))
	require.NoError(err)
	j, err := newTokenRenewalJob(ctx, rw, rw, kmsCache)
	require.NoError(err)
	err = sche.RegisterJob(ctx, j)
	require.NoError(err)
	cs, err := repo.CreateCredentialStore(ctx, credStoreIn)
	require.NoError(err)

	libPath := path.Join("database", "creds", "opened")
	libIn, err := NewCredentialLibrary(cs.GetPublicId(), libPath)
	require.NoError(err)
	cl, err := repo.CreateCredentialLibrary(ctx, prj.GetPublicId(), libIn)
	require.NoError(err)

	at := authtoken.TestAuthToken(t, conn, kmsCache, org.GetPublicId())
	uId := at.GetIamUserId()
	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})
	tar := tcp.TestTarget(ctx, t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	sess1 := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})
	sess2 := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	repoToken := allocToken()
	require.NoError(rw.LookupWhere(ctx, &repoToken, "token_hmac = ?", []any{cs.outputToken.TokenHmac}))

	r, err := newCredentialCleanupJob(ctx, rw)
	require.NoError(err)

	_, sess1Cred1 := testVaultCred(t, conn, v, cl, sess1, repoToken, ActiveCredential, 5*time.Hour)
	_, sess1Cred2 := testVaultCred(t, conn, v, cl, sess1, repoToken, ActiveCredential, 5*time.Hour)
	_, sess1Cred3 := testVaultCred(t, conn, v, cl, sess1, repoToken, ActiveCredential, 5*time.Hour)
	_, sess2Cred := testVaultCred(t, conn, v, cl, sess2, repoToken, ActiveCredential, 5*time.Hour)

	// No credentials should be cleaned up
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(0, r.numCreds)

	// Delete sess1
	count, err := rw.Delete(ctx, sess1)
	require.NoError(err)
	assert.Equal(1, count)

	// Credentials are still in the revoke state so none should be deleted yet
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(0, r.numCreds)

	query, queryArgs := sess1Cred1.updateStatusQuery(RevokedCredential)
	count, err = rw.Exec(ctx, query, queryArgs)
	require.NoError(err)
	assert.Equal(1, count)

	query, queryArgs = sess1Cred2.updateStatusQuery(ExpiredCredential)
	count, err = rw.Exec(ctx, query, queryArgs)
	require.NoError(err)
	assert.Equal(1, count)

	query, queryArgs = sess1Cred3.updateStatusQuery(UnknownCredentialStatus)
	count, err = rw.Exec(ctx, query, queryArgs)
	require.NoError(err)
	assert.Equal(1, count)

	query, queryArgs = sess2Cred.updateStatusQuery(RevokedCredential)
	count, err = rw.Exec(ctx, query, queryArgs)
	require.NoError(err)
	assert.Equal(1, count)

	// Only the three credentials associated with the deleted session should be deleted
	err = r.Run(ctx, 0)
	require.NoError(err)
	assert.Equal(3, r.numCreds)

	// Session 1 creds should no longer exist
	lookupCred := allocCredential()
	lookupCred.PublicId = sess1Cred1.PublicId
	require.Error(rw.LookupById(ctx, lookupCred))
	lookupCred.PublicId = sess1Cred2.PublicId
	require.Error(rw.LookupById(ctx, lookupCred))
	lookupCred.PublicId = sess1Cred3.PublicId
	require.Error(rw.LookupById(ctx, lookupCred))

	// Session 2 creds should still exist but be revoked
	lookupCred.PublicId = sess2Cred.PublicId
	require.NoError(rw.LookupById(ctx, lookupCred))
	assert.Equal(string(RevokedCredential), lookupCred.Status)
}

func TestVaultJobsWorkerFilters(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStore(t, conn, wrapper, prj.PublicId, "http://vault", "vault-token", "accessor", WithWorkerFilter("true == true"))
	lib := TestCredentialLibraries(t, conn, wrapper, cs.PublicId, globals.UnspecifiedCredentialType, 1)[0]
	token := cs.Token()

	csNoFilter := TestCredentialStore(t, conn, wrapper, prj.PublicId, "http://vault", "vault-token-no-filter", "accessor")
	libNoFilter := TestCredentialLibraries(t, conn, wrapper, csNoFilter.PublicId, globals.UnspecifiedCredentialType, 1)[0]
	tokenNoFilter := csNoFilter.Token()

	iamRepo := iam.TestRepo(t, conn, wrapper)
	session := session.TestDefaultSession(t, conn, wrapper, iamRepo)

	// Create credential with filter
	got, err := newCredential(ctx, lib.GetPublicId(), "some/vault/credential", token.GetTokenHmac(), time.Minute)
	require.NoError(err)
	id, err := newCredentialId(ctx)
	assert.NoError(err)
	got.PublicId = id
	query, queryValues := insertQuery(got, session.PublicId)
	require.NoError(err)
	rows, err := rw.Exec(ctx, query, queryValues)
	assert.Equal(1, rows)
	assert.NoError(err)

	// Validate renew/revoke token query includes worker filter
	ps := &renewRevokeStore{Store: allocClientStore()}
	ps.Store.PublicId = cs.PublicId
	err = rw.LookupById(ctx, ps)
	require.NoError(err)
	assert.Equal("true == true", ps.Store.WorkerFilter)

	// Validate renew/revoke credential query includes worker filter
	cred := &privateCredential{PublicId: id}
	err = rw.LookupById(ctx, cred)
	require.NoError(err)
	assert.Equal("true == true", cred.WorkerFilter)

	// Create credential without filter
	got, err = newCredential(ctx, libNoFilter.GetPublicId(), "some/vault/credential", tokenNoFilter.GetTokenHmac(), time.Minute)
	require.NoError(err)
	idNoFilter, err := newCredentialId(ctx)
	assert.NoError(err)
	got.PublicId = idNoFilter
	query, queryValues = insertQuery(got, session.PublicId)
	require.NoError(err)
	rows, err = rw.Exec(ctx, query, queryValues)
	assert.Equal(1, rows)
	assert.NoError(err)

	// Validate renew/revoke token query does not include worker filter
	ps = &renewRevokeStore{Store: allocClientStore()}
	ps.Store.PublicId = csNoFilter.PublicId
	err = rw.LookupById(ctx, ps)
	require.NoError(err)
	assert.Empty(ps.Store.WorkerFilter)

	// Validate renew/revoke credential query does not include worker filter
	cred = &privateCredential{PublicId: idNoFilter}
	err = rw.LookupById(ctx, cred)
	require.NoError(err)
	assert.Empty(cred.WorkerFilter)
}
