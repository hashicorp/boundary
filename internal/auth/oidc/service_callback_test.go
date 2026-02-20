// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	authStore "github.com/hashicorp/boundary/internal/auth/store"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/boundary/internal/iam"
	iamStore "github.com/hashicorp/boundary/internal/iam/store"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/cap/oidc"
	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/hashicorp/go-bexpr/grammar"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/go-secure-stdlib/strutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Callback(t *testing.T) {
	// DO NOT run these tests under t.Parallel(), there be dragons because of dependencies on the
	// Database and TestProvider state
	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)

	testCtx := context.Background()
	opt := event.TestWithObservationSink(t)
	c := event.TestEventerConfig(t, "Test_StartAuth_to_Callback", opt)
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	c.EventerConfig.TelemetryEnabled = true
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-Test_Callback", event.WithEventerConfig(&c.EventerConfig)))
	// some standard factories for unit tests which
	// are used in the Callback(...) call
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	repoFn := func() (*Repository, error) {
		return NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}
	atRepo, err := atRepoFn()
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	// a very simple test mock controller, that simply responds with a 200 OK to every
	// request.
	testController := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
	}))
	defer testController.Close()

	// test provider for the tests (see the oidc package docs for more info)
	// it will provide discovery, JWKs, a token endpoint, etc for these tests.
	tp := oidc.StartTestProvider(t)
	tpCert, err := ParseCertificates(ctx, tp.CACert())
	require.NoError(t, err)
	_, _, tpAlg, _ := tp.SigningKeys()

	// a reusable test authmethod for the unit tests
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		"alice-rp", "fido",
		WithCertificates(tpCert...),
		WithSigningAlgs(Alg(tpAlg)),
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]))

	// set this as the primary so users will be created on first login
	iam.TestSetPrimaryAuthMethod(t, iamRepo, org, testAuthMethod.PublicId)

	// a reusable oidc.Provider for the tests
	testProvider, err := convertToProvider(ctx, testAuthMethod)
	require.NoError(t, err)
	testConfigHash, err := testProvider.ConfigHash()
	require.NoError(t, err)

	// a reusable token request id for the tests.
	testTokenRequestId, err := authtoken.NewAuthTokenId(ctx)
	require.NoError(t, err)

	// usuable nonce for the unit tests
	testNonce := "nonce"

	// define the audiences the test provider will accept for the unit tests.
	tp.SetCustomAudience("foo", "alice-rp")

	// define a second test auth method, which is in an InactiveState for the unit tests.
	org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper2, err := kmsCache.GetWrapper(ctx, org2.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod2 := TestAuthMethod(t, conn, databaseWrapper2, org2.PublicId, InactiveState,
		"alice-rp", "fido",
		WithAudClaims("foo"),
		WithMaxAge(-1), // oidc library has a 1 min leeway
		WithCertificates(tpCert...),
		WithSigningAlgs(Alg(tpAlg)),
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]))
	// define a second test provider based on the inactive test auth method
	testProvider2, err := convertToProvider(ctx, testAuthMethod2)
	require.NoError(t, err)
	testConfigHash2, err := testProvider2.ConfigHash()
	require.NoError(t, err)

	tests := []struct {
		name              string
		setup             func()               // provide a simple way to do some prework before the test.
		oidcRepoFn        OidcRepoFactory      // returns a new oidc repo
		iamRepoFn         IamRepoFactory       // returns a new iam repo
		atRepoFn          AuthTokenRepoFactory // returns a new auth token repo
		am                *AuthMethod          // the authmethod for the test
		state             string               // state parameter for test provider and Callback(...)
		code              string               // code parameter for test provider and Callback(...)
		wantSubject       string               // sub claim from id token
		wantInfoName      string               // name claim from userinfo
		wantInfoEmail     string               // email claim from userinfo
		wantFinalRedirect string               // final redirect from Callback(...)
		wantErrMatch      *errors.Template     // error template to match
		wantErrContains   string               // error string should contain
	}{
		{
			name:              "simple", // must remain the first test
			oidcRepoFn:        repoFn,
			iamRepoFn:         iamRepoFn,
			atRepoFn:          atRepoFn,
			am:                testAuthMethod,
			state:             testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:              "simple",
			wantFinalRedirect: "https://testcontroler.com/hi-alice",
			wantSubject:       "simple@example.com",
			wantInfoName:      "alice doe-eve",
			wantInfoEmail:     "alice@example.com",
		},
		{
			name:              "dup", // must follow "simple" unit test
			oidcRepoFn:        repoFn,
			iamRepoFn:         iamRepoFn,
			atRepoFn:          atRepoFn,
			am:                testAuthMethod,
			state:             testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:              "simple",
			wantFinalRedirect: "https://testcontroler.com/hi-alice",
			wantSubject:       "dup@example.com",
			wantInfoName:      "alice doe-eve",
			wantInfoEmail:     "alice@example.com",
		},
		{
			name: "inactive-valid",
			setup: func() {
				acct := TestAccount(t, conn, testAuthMethod2, "inactive-valid@example.com")
				_ = iam.TestUser(t, iamRepo, org2.PublicId, iam.WithAccountIds(acct.PublicId))
			},
			oidcRepoFn:        repoFn,
			iamRepoFn:         iamRepoFn,
			atRepoFn:          atRepoFn,
			am:                testAuthMethod2,
			state:             testState(t, testAuthMethod2, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash2, testNonce),
			code:              "simple",
			wantFinalRedirect: "https://testcontroler.com/hi-alice",
			wantSubject:       "inactive-valid@example.com",
			wantInfoName:      "alice doe-eve",
			wantInfoEmail:     "alice@example.com",
		},
		{
			name:            "missing-oidc-repo-fn",
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing oidc repository",
		},
		{
			name:            "missing-iam-repo-fn",
			oidcRepoFn:      repoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing iam repository",
		},
		{
			name:            "missing-at-repo-fn",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			am:              testAuthMethod,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth token repository",
		},
		{
			name:            "missing-state",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			code:            "simple",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing state",
		},
		{
			name:            "missing-code",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing code",
		},
		{
			name:            "missing-auth-method",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              func() *AuthMethod { return nil }(),
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method",
		},
		{
			name:            "mismatch-auth-method",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			state:           testState(t, testAuthMethod2, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "auth method id does not match request wrapper auth method id",
		},
		{
			name:            "bad-state-encoding",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			state:           "unable to decode message",
			code:            "simple",
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to decode message",
		},
		{
			name:            "inactive-with-config-change",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod2,
			state:           testState(t, testAuthMethod2, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", 1, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.AuthMethodInactive),
			wantErrContains: "configuration changed during in-flight authentication attempt",
		},
		{
			name:            "expired-attempt",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, -20*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.AuthAttemptExpired),
			wantErrContains: "request state has expired",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// start with no tokens in the db
			_, err := rw.Exec(ctx, "delete from auth_token", nil)
			require.NoError(err)
			// start with no users in the db
			excludeUsers := []any{globals.AnonymousUserId, globals.AnyAuthenticatedUserId, globals.RecoveryUserId}
			_, err = rw.Exec(ctx, "delete from iam_user where public_id not in(?, ?, ?)", excludeUsers)
			require.NoError(err)
			// start with no oplog entries
			_, err = rw.Exec(ctx, "delete from oplog_entry", nil)
			require.NoError(err)

			if tt.setup != nil {
				tt.setup()
			}

			// the test provider is stateful, so we need to configure
			// it for this unit test.
			tp.SetExpectedAuthNonce(testNonce)
			if tt.am != nil {
				tp.SetClientCreds(tt.am.ClientId, tt.am.ClientSecret)
				tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, tt.am.ApiUrl)
				tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
			}
			if tt.code != "" {
				tp.SetExpectedAuthCode(tt.code)
			}
			if tt.state != "" {
				tp.SetExpectedState(tt.state)
			}
			tp.SetExpectedSubject(tt.wantSubject)

			info := map[string]any{}
			if tt.wantSubject != "" {
				info["sub"] = tt.wantSubject
			}
			if tt.wantInfoEmail != "" {
				info["email"] = tt.wantInfoEmail
			}
			if tt.wantInfoName != "" {
				info["name"] = tt.wantInfoName
			}
			if len(info) > 0 {
				tp.SetUserInfoReply(info)
			}
			gotRedirect, err := Callback(ctx,
				tt.oidcRepoFn,
				tt.iamRepoFn,
				tt.atRepoFn,
				tt.am,
				tt.state,
				tt.code,
			)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(gotRedirect)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)
				assert.Contains(err.Error(), tt.wantErrContains)

				// make sure there are no tokens in the db..
				var tokens []*authtoken.AuthToken
				err := rw.SearchWhere(ctx, &tokens, "1=?", []any{1})
				require.NoError(err)
				assert.Equal(0, len(tokens))

				// make sure there weren't any oplog entries written.
				var entries []*oplog.Entry
				err = rw.SearchWhere(ctx, &entries, "1=?", []any{1})
				require.NoError(err)
				amId := ""
				if tt.am != nil {
					amId = tt.am.PublicId
				}
				require.Equalf(0, len(entries), "should not have found oplog entry for %s", amId)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantFinalRedirect, gotRedirect)

			sinkFileName := c.ObservationEvents.Name()
			defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(sinkFileName)
			require.NoError(err)
			got := &cloudevents.Event{}
			err = json.Unmarshal(b, got)
			require.NoErrorf(err, "json: %s", string(b))
			details, ok := got.Data.(map[string]any)["details"]
			require.True(ok)
			for _, key := range details.([]any) {
				assert.Contains(key.(map[string]any)["payload"], "user_id")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_start")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_end")
			}

			// make sure a pending token was created.
			var tokens []*authtoken.AuthToken
			err = rw.SearchWhere(ctx, &tokens, "1=?", []any{1})
			require.NoError(err)
			require.Equal(1, len(tokens))
			tk, err := atRepo.LookupAuthToken(ctx, tokens[0].PublicId)
			require.NoError(err)
			assert.Equal(tk.Status, string(authtoken.PendingStatus))

			// make sure the account was updated properly
			var acct Account
			err = rw.LookupWhere(ctx, &acct, "auth_method_id = ? and subject = ?", []any{tt.am.PublicId, tt.wantSubject})
			require.NoError(err)
			assert.Equal(tt.wantInfoEmail, acct.Email)
			assert.Equal(tt.wantInfoName, acct.FullName)
			assert.Equal(tk.AuthAccountId, acct.PublicId)

			// make sure the token is properly assoc with the
			// logged in user
			var users []*iam.User
			err = rw.SearchWhere(ctx, &users, "public_id not in(?, ?, ?)", excludeUsers)
			require.NoError(err)
			require.Equal(1, len(users))
			assert.Equal(tk.IamUserId, users[0].PublicId)

			// check the oplog entries.
			var entries []*oplog.Entry
			err = rw.SearchWhere(ctx, &entries, "1=?", []any{1})
			require.NoError(err)
			oplogWrapper, err := kmsCache.GetWrapper(ctx, tt.am.ScopeId, kms.KeyPurposeOplog)
			require.NoError(err)
			types, err := oplog.NewTypeCatalog(testCtx,
				oplog.Type{Interface: new(store.Account), Name: "auth_oidc_account"},
				oplog.Type{Interface: new(iamStore.User), Name: "iam_user"},
				oplog.Type{Interface: new(authStore.Account), Name: "auth_account"},
			)
			require.NoError(err)

			cnt := 0
			foundAcct, foundOidcAcct := false, false
			for _, e := range entries {
				cnt += 1
				e.Wrapper = oplogWrapper
				err := e.DecryptData(ctx)
				require.NoError(err)
				msgs, err := e.UnmarshalData(ctx, types)
				require.NoError(err)
				for _, m := range msgs {
					switch m.TypeName {
					case "auth_oidc_account":
						foundOidcAcct = true
						t.Log("test: ", tt.name, "found oidc: ", m)
					case "iam_user":
						t.Log("test: ", tt.name, "found iam user: ", m)
					case "auth_account":
						foundAcct = true
						t.Log("test: ", tt.name, "found acct", m)
					}
				}
			}
			assert.Truef(foundAcct, "expected to find auth account oplog entry")
			assert.Truef(foundOidcAcct, "expected to find auth oidc account oplog entry")
		})
	}
	t.Run("replay-attack-with-dup-state", func(t *testing.T) {
		// a test to ensure that replays of duplicate states
		// are rejected and produce an appropriate error.

		assert, require := assert.New(t), require.New(t)

		// start with no tokens in the db
		_, err := rw.Exec(ctx, "delete from auth_token", nil)
		require.NoError(err)
		// start with no users in the db
		excludeUsers := []any{globals.AnonymousUserId, globals.AnyAuthenticatedUserId, globals.RecoveryUserId}
		_, err = rw.Exec(ctx, "delete from iam_user where public_id not in(?, ?, ?)", excludeUsers)
		require.NoError(err)
		// start with no oplog entries
		_, err = rw.Exec(ctx, "delete from oplog_entry", nil)
		require.NoError(err)

		// prime the test provider's state for the test
		tp.SetClientCreds(testAuthMethod.ClientId, testAuthMethod.ClientSecret)
		tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, testController.URL)
		tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
		state := testState(t, testAuthMethod, kmsCache, testTokenRequestId, 20*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce)
		tp.SetExpectedAuthCode("simple")
		tp.SetExpectedState(state)

		wantSubject := "replay-attack-with-dup-state@example.com"
		tp.SetExpectedSubject(wantSubject)

		tp.SetUserInfoReply(map[string]any{"sub": wantSubject})
		tp.SetExpectedAuthNonce(testNonce)
		config := event.EventerConfig{
			ObservationsEnabled: true,
		}
		testLock := &sync.Mutex{}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Mutex: testLock,
			Name:  "test",
		})
		e, err := event.NewEventer(testLogger, testLock, "replay-attack-with-dup-state", config)
		require.NoError(err)
		ctx, err := event.NewEventerContext(ctx, e)
		require.NoError(err)
		// the first request should succeed.
		gotRedirect, err := Callback(ctx,
			repoFn,
			iamRepoFn,
			atRepoFn,
			testAuthMethod,
			state,
			"simple",
		)
		require.NoError(err)
		require.NotNil(gotRedirect)

		// the replay should raise an error.
		gotRedirect2, err := Callback(ctx,
			repoFn,
			iamRepoFn,
			atRepoFn,
			testAuthMethod,
			state,
			"simple",
		)
		require.Error(err)
		require.Empty(gotRedirect2)
		assert.Truef(errors.Match(errors.T(errors.Forbidden), err), "want err code: %q got: %q", errors.InvalidParameter, err)
		assert.Contains(err.Error(), "not a unique request")
	})
}

// Test_StartAuth_to_Callback will test if we can successfully
// test StartAuth(...) through Callback(...)
func Test_StartAuth_to_Callback(t *testing.T) {
	t.Run("startAuth-to-Callback", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		c := event.TestEventerConfig(t, "Test_StartAuth_to_Callback")
		testLock := &sync.Mutex{}
		testLogger := hclog.New(&hclog.LoggerOptions{
			Mutex: testLock,
			Name:  "test",
		})
		require.NoError(event.InitSysEventer(testLogger, testLock, "use-Test_StartAuth_to_Callback", event.WithEventerConfig(&c.EventerConfig)))
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		// start with no tokens in the db
		_, err := rw.Exec(ctx, "delete from auth_token", nil)
		require.NoError(err)
		// start with no users in the db
		excludeUsers := []any{globals.AnonymousUserId, globals.AnyAuthenticatedUserId, globals.RecoveryUserId}
		_, err = rw.Exec(ctx, "delete from iam_user where public_id not in(?, ?, ?)", excludeUsers)
		require.NoError(err)
		// start with no oplog entries
		_, err = rw.Exec(ctx, "delete from oplog_entry", nil)
		require.NoError(err)

		rootWrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, rootWrapper)

		// func pointers for the test controller.
		iamRepoFn := func() (*iam.Repository, error) {
			return iam.NewRepository(ctx, rw, rw, kmsCache)
		}
		repoFn := func() (*Repository, error) {
			return NewRepository(ctx, rw, rw, kmsCache)
		}
		atRepoFn := func() (*authtoken.Repository, error) {
			return authtoken.NewRepository(ctx, rw, rw, kmsCache)
		}
		atRepo, err := atRepoFn()
		require.NoError(err)

		controller := startTestControllerSrv(t, repoFn, iamRepoFn, atRepoFn)

		iamRepo := iam.TestRepo(t, conn, rootWrapper)
		org, _ := iam.TestScopes(t, iamRepo)

		databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)

		// the testing OIDC provider (it's a functional fake, see the package docs)
		tp := oidc.StartTestProvider(t)
		tpCert, err := ParseCertificates(ctx, tp.CACert())
		require.NoError(err)
		_, _, tpAlg, _ := tp.SigningKeys()

		endToEndAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePublicState,
			"end-to-end-rp", "fido",
			WithCertificates(tpCert...),
			WithSigningAlgs(Alg(tpAlg)),
			WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
			WithApiUrl(TestConvertToUrls(t, controller.Addr())[0]))

		// need the updated org version, so we can set the primary auth method id
		org, _ = iamRepo.LookupScope(ctx, org.PublicId)
		require.NoError(err)
		iam.TestSetPrimaryAuthMethod(t, iamRepo, org, endToEndAuthMethod.PublicId)

		// the test controller is stateful and needs to know what auth method id
		// it's suppose to operate on
		controller.SetAuthMethod(endToEndAuthMethod)

		authUrl, _, err := StartAuth(ctx, repoFn, endToEndAuthMethod.PublicId)
		require.NoError(err)

		authParams, err := url.ParseQuery(authUrl.RawQuery)
		require.NoError(err)
		require.Equal(1, len(authParams["nonce"]))
		require.Equal(1, len(authParams["state"]))

		// the TestProvider is stateful and needs to be configured for the upcoming requests.
		tp.SetExpectedState(authParams["state"][0])
		tp.SetExpectedAuthNonce(authParams["nonce"][0])
		tp.SetExpectedAuthCode("simple")
		tp.SetClientCreds(endToEndAuthMethod.ClientId, endToEndAuthMethod.ClientSecret)
		tpAllowedRedirect := controller.CallbackUrl()
		tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})

		client := tp.HTTPClient()
		// this http request will:
		// * 1) go to the TestProvider, where auth/authz will be faked.
		// * 2) TestProvider will send 302 back to the client for callback
		// * 3) 302 redirected to testControllerSrv's callback handler
		// * 4) callback handler will exchange the token with the TestProvider
		// * 5) callback will send 302 back to client with final redirect
		// * 6) 302 redirected to testControllerSrv's final redirect handler.
		// * 7) final redirect handler sends "Congratulations" msg back to client.
		//
		// If this succeeds, then the service functions of StartAuth(...) and
		// Callback(...) are successfully working together.
		resp, err := client.Get(authUrl.String())
		require.NoError(err)
		defer resp.Body.Close()
		contents, err := io.ReadAll(resp.Body)
		require.NoError(err)
		require.Containsf(string(contents), "Congratulations", "expected \"Congratulations\" on successful oidc authentication and got: %s", string(contents))

		// check to make sure there's a pending token, after the successful callback
		var tokens []*authtoken.AuthToken
		err = rw.SearchWhere(ctx, &tokens, "1=?", []any{1})
		require.NoError(err)
		require.Equal(1, len(tokens))
		tk, err := atRepo.LookupAuthToken(ctx, tokens[0].PublicId)
		require.NoError(err)
		assert.Equal(tk.Status, string(authtoken.PendingStatus))
	})
}

func Test_ManagedGroupFiltering(t *testing.T) {
	// DO NOT run these tests under t.Parallel()

	// A note about this test: other tests handle checking managed group
	// membership, creation, etc. This test is only scoped to checking that
	// given reasonable data in the jwt/userinfo, the result of a callback call
	// results in association with the proper managed groups.

	ctx := context.Background()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	rootWrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, rootWrapper)
	opt := event.TestWithObservationSink(t)
	c := event.TestEventerConfig(t, "Test_StartAuth_to_Callback", opt)
	testLock := &sync.Mutex{}
	testLogger := hclog.New(&hclog.LoggerOptions{
		Mutex: testLock,
		Name:  "test",
	})
	c.EventerConfig.TelemetryEnabled = true
	require.NoError(t, event.InitSysEventer(testLogger, testLock, "use-Test_ManagedGroupFiltering", event.WithEventerConfig(&c.EventerConfig)))
	// some standard factories for unit tests which
	// are used in the Callback(...) call
	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(ctx, rw, rw, kmsCache)
	}
	repoFn := func() (*Repository, error) {
		// Set a low limit to test that the managed group listing overrides the limit
		return NewRepository(ctx, rw, rw, kmsCache, WithLimit(1))
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(ctx, rw, rw, kmsCache)
	}

	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	// a very simple test mock controller, that simply responds with a 200 OK to
	// every request.
	testController := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
	}))
	defer testController.Close()

	// test provider for the tests (see the oidc package docs for more info)
	// it will provide discovery, JWKs, a token endpoint, etc for these tests.
	tp := oidc.StartTestProvider(t)
	tpCert, err := ParseCertificates(ctx, tp.CACert())
	require.NoError(t, err)
	_, _, tpAlg, _ := tp.SigningKeys()

	// a reusable test authmethod for the unit tests
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		"alice-rp", "fido",
		WithCertificates(tpCert...),
		WithSigningAlgs(Alg(tpAlg)),
		WithIssuer(TestConvertToUrls(t, tp.Addr())[0]),
		WithApiUrl(TestConvertToUrls(t, testController.URL)[0]))

	// set this as the primary so users will be created on first login
	iam.TestSetPrimaryAuthMethod(t, iamRepo, org, testAuthMethod.PublicId)

	// Create an account so it's a known account id
	sub := "alice@example.com"
	account := TestAccount(t, conn, testAuthMethod, sub)

	// Create two managed groups. We'll use these in tests to set filters and
	// then check that the user belongs to the ones we expect.
	mgs := []*ManagedGroup{
		TestManagedGroup(t, conn, testAuthMethod, TestFakeManagedGroupFilter),
		TestManagedGroup(t, conn, testAuthMethod, TestFakeManagedGroupFilter),
	}

	// A reusable oidc.Provider for the tests
	testProvider, err := convertToProvider(ctx, testAuthMethod)
	require.NoError(t, err)
	testConfigHash, err := testProvider.ConfigHash()
	require.NoError(t, err)

	// Set up the provider a bit
	testNonce := "nonce"
	tp.SetExpectedAuthNonce(testNonce)
	code := "simple"
	tp.SetExpectedAuthCode(code)
	tp.SetExpectedSubject(sub)
	tp.SetCustomAudience("foo", "alice-rp")
	info := map[string]any{
		"roles":  []string{"user", "operator"},
		"sub":    "alice@example.com",
		"email":  "alice-alias@example.com",
		"name":   "alice doe joe foe",
		"co:lon": "colon",
	}
	tp.SetUserInfoReply(info)

	repo, err := repoFn()
	require.NoError(t, err)

	tests := []struct {
		name        string
		filters     []string        // Should always be length 2, and specify the filters to use for the test
		matchingMgs []*ManagedGroup // The public IDs of the managed groups we expect the user to be in
	}{
		{
			name: "no match",
			filters: []string{
				TestFakeManagedGroupFilter,
				TestFakeManagedGroupFilter,
			},
		},
		{
			name: "token match",
			filters: []string{
				`"/token/nonce" == "nonce"`,
				TestFakeManagedGroupFilter,
			},
			matchingMgs: mgs[0:1],
		},
		{
			name: "token double match",
			filters: []string{
				`"/token/nonce" == "nonce"`,
				`"/token/name" == "Alice Doe Smith"`,
			},
			matchingMgs: mgs[0:2],
		},
		{
			name: "userinfo double match",
			filters: []string{
				`"user" in "/userinfo/roles"`,
				`"/userinfo/email" == "alice-alias@example.com"`,
			},
			matchingMgs: mgs[0:2],
		},
		{
			name: "userinfo match only",
			filters: []string{
				`"/token/nonce" == "not-nonce"`,
				`"/userinfo/email" == "alice-alias@example.com"`,
			},
			matchingMgs: mgs[1:2],
		},
		{
			name: "colon test",
			filters: []string{
				TestFakeManagedGroupFilter,
				`"/userinfo/co:lon" == "colon"`,
			},
			matchingMgs: mgs[1:2],
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			// A unique token ID for each test
			testTokenRequestId, err := authtoken.NewAuthTokenId(ctx)
			require.NoError(err)

			// the test provider is stateful, so we need to configure
			// it for this unit test.
			tp.SetClientCreds(testAuthMethod.ClientId, testAuthMethod.ClientSecret)
			tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, testAuthMethod.ApiUrl)
			tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})

			state := testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce)
			tp.SetExpectedState(state)

			// Set the filters on the MGs for this test. First we need to get the current versions.
			currMgs, ttime, err := repo.ListManagedGroups(ctx, testAuthMethod.PublicId, WithLimit(-1))
			require.NoError(err)
			// Transaction timestamp should be within ~10 seconds of now
			assert.True(time.Now().Before(ttime.Add(10 * time.Second)))
			assert.True(time.Now().After(ttime.Add(-10 * time.Second)))
			require.Len(currMgs, 2)
			currVersionMap := map[string]uint32{
				currMgs[0].PublicId: currMgs[0].Version,
				currMgs[1].PublicId: currMgs[1].Version,
			}
			for i, filter := range tt.filters {
				mgs[i].Filter = filter
				_, numUpdated, err := repo.UpdateManagedGroup(ctx, org.PublicId, mgs[i], currVersionMap[mgs[i].PublicId], []string{"Filter"})
				require.Equal(numUpdated, 1)
				require.NoError(err)
			}
			// Run the callback
			_, err = Callback(ctx,
				repoFn,
				iamRepoFn,
				atRepoFn,
				testAuthMethod,
				state,
				code,
			)
			require.NoError(err)
			sinkFileName := c.ObservationEvents.Name()
			defer func() { _ = os.WriteFile(sinkFileName, nil, 0o666) }()
			b, err := os.ReadFile(sinkFileName)
			require.NoError(err)
			got := &cloudevents.Event{}
			err = json.Unmarshal(b, got)
			require.NoErrorf(err, "json: %s", string(b))
			details, ok := got.Data.(map[string]any)["details"]
			require.True(ok)
			for _, key := range details.([]any) {
				assert.Contains(key.(map[string]any)["payload"], "user_id")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_start")
				assert.Contains(key.(map[string]any)["payload"], "auth_token_end")
			}
			// Ensure that we get the expected groups
			memberships, err := repo.ListManagedGroupMembershipsByMember(ctx, account.PublicId, WithLimit(-1))
			require.NoError(err)
			assert.Equal(len(tt.matchingMgs), len(memberships))
			var matchingIds []string
			for _, mg := range tt.matchingMgs {
				matchingIds = append(matchingIds, mg.PublicId)
			}
			for _, mg := range memberships {
				assert.True(strutil.StrListContains(matchingIds, mg.ManagedGroupId))
			}
		})
	}
}

func Test_normalizeInSyntaxClaims(t *testing.T) {
	tests := []struct {
		name         string
		filter       string
		evalData     map[string]any
		expectedData map[string]any
	}{
		{
			name:   "IN normalizes string to array",
			filter: `"operator" in "/userinfo/roles"`,
			evalData: map[string]any{
				"userinfo": map[string]any{
					"roles": "operator",
				},
			},
			expectedData: map[string]any{
				"userinfo": map[string]any{
					"roles": []string{"operator"},
				},
			},
		},
		{
			name:   "CONTAINS does not normalize",
			filter: `"/userinfo/email" contains "@example.com"`,
			evalData: map[string]any{
				"userinfo": map[string]any{
					"email": "test@example.com",
				},
			},
			expectedData: map[string]any{
				"userinfo": map[string]any{
					"email": "test@example.com",
				},
			},
		},
		{
			name:   "NOT IN normalizes string to array",
			filter: `"admin" not in "/userinfo/roles"`,
			evalData: map[string]any{
				"userinfo": map[string]any{
					"roles": "user",
				},
			},
			expectedData: map[string]any{
				"userinfo": map[string]any{
					"roles": []string{"user"},
				},
			},
		},
		{
			name:   "Token nested path - IN normalizes",
			filter: `"infosec" in "/token/custom/department"`,
			evalData: map[string]any{
				"token": map[string]any{
					"custom": map[string]any{
						"department": "infosec",
					},
				},
			},
			expectedData: map[string]any{
				"token": map[string]any{
					"custom": map[string]any{
						"department": []string{"infosec"},
					},
				},
			},
		},
		{
			name:   "OR with multiple departments - both paths normalized",
			filter: `"infosec" in "/token/custom/department" or "ops" in "/token/custom/department"`,
			evalData: map[string]any{
				"token": map[string]any{
					"custom": map[string]any{
						"department": "infosec",
					},
				},
			},
			expectedData: map[string]any{
				"token": map[string]any{
					"custom": map[string]any{
						"department": []string{"infosec"},
					},
				},
			},
		},
		{
			name:   "NOT wrapping IN - UnaryExpression",
			filter: `not "banned" in "/userinfo/roles"`,
			evalData: map[string]any{
				"userinfo": map[string]any{
					"roles": "user",
				},
			},
			expectedData: map[string]any{
				"userinfo": map[string]any{
					"roles": []string{"user"},
				},
			},
		},
		{
			name:   "IN AND CONTAINS - only IN normalized",
			filter: `"operator" in "/userinfo/roles" and "/userinfo/email" contains "@example.com"`,
			evalData: map[string]any{
				"userinfo": map[string]any{
					"roles": "operator",
					"email": "testuser@example.com",
				},
			},
			expectedData: map[string]any{
				"userinfo": map[string]any{
					"roles": []string{"operator"},
					"email": "testuser@example.com",
				},
			},
		},
		{
			name:   "IN OR CONTAINS same path - IN causes normalization",
			filter: `"admin" in "/userinfo/roles" or "/userinfo/roles" contains "admin"`,
			evalData: map[string]any{
				"userinfo": map[string]any{
					"roles": "operator",
				},
			},
			expectedData: map[string]any{
				"userinfo": map[string]any{
					"roles": []string{"operator"},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			ast, err := grammar.Parse("", []byte(tt.filter))
			require.NoError(t, err)
			normalizeInSyntaxClaims(ast.(grammar.Expression), tt.filter, tt.evalData)
			assert.Equal(tt.expectedData, tt.evalData)
		})
	}
}
