package oidc

import (
	"context"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	authStore "github.com/hashicorp/boundary/internal/auth/store"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	iamStore "github.com/hashicorp/boundary/internal/iam/store"

	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/cap/oidc"
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

	iamRepoFn := func() (*iam.Repository, error) {
		return iam.NewRepository(rw, rw, kmsCache)
	}
	repoFn := func() (*Repository, error) {
		return NewRepository(rw, rw, kmsCache)
	}
	atRepoFn := func() (*authtoken.Repository, error) {
		return authtoken.NewRepository(rw, rw, kmsCache)
	}
	atRepo, err := atRepoFn()
	require.NoError(t, err)

	iamRepo := iam.TestRepo(t, conn, rootWrapper)
	org, _ := iam.TestScopes(t, iamRepo)

	databaseWrapper, err := kmsCache.GetWrapper(ctx, org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testController := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(200)
	}))
	defer testController.Close()

	tp := oidc.StartTestProvider(t)
	tpCert, err := ParseCertificates(tp.CACert())
	require.NoError(t, err)
	_, _, tpAlg, _ := tp.SigningKeys()

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePublicState,
		TestConvertToUrls(t, tp.Addr())[0],
		"alice-rp", "fido",
		WithCertificates(tpCert...),
		WithSigningAlgs(Alg(tpAlg)),
		WithCallbackUrls(TestConvertToUrls(t, testController.URL)[0]))

	iam.TestSetPrimaryAuthMethod(t, iamRepo, org, testAuthMethod.PublicId)

	testProvider, err := convertToProvider(ctx, testAuthMethod)
	require.NoError(t, err)
	testConfigHash, err := testProvider.ConfigHash()
	require.NoError(t, err)

	testTokenRequestId, err := authtoken.NewAuthTokenId()
	require.NoError(t, err)

	testNonce := "nonce"
	tp.SetExpectedAuthNonce(testNonce)

	tp.SetCustomAudience("foo", "alice-rp")

	org2, _ := iam.TestScopes(t, iam.TestRepo(t, conn, rootWrapper))
	databaseWrapper2, err := kmsCache.GetWrapper(ctx, org2.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod2 := TestAuthMethod(t, conn, databaseWrapper2, org2.PublicId, InactiveState,
		TestConvertToUrls(t, tp.Addr())[0],
		"alice-rp", "fido",
		WithAudClaims("foo"),
		WithMaxAge(-1), // oidc library has a 1 min leeway
		WithCertificates(tpCert...),
		WithSigningAlgs(Alg(tpAlg)),
		WithCallbackUrls(TestConvertToUrls(t, testController.URL)[0]))
	testProvider2, err := convertToProvider(ctx, testAuthMethod2)
	require.NoError(t, err)
	testConfigHash2, err := testProvider2.ConfigHash()
	require.NoError(t, err)

	setupFn := func() {
		acct := TestAccount(t, conn, testAuthMethod2.PublicId, TestConvertToUrls(t, tp.Addr())[0], "alice@example.com")
		_ = iam.TestUser(t, iamRepo, org2.PublicId, iam.WithAccountIds(acct.PublicId))
	}

	tests := []struct {
		name              string
		setup             func()
		oidcRepoFn        OidcRepoFactory
		iamRepoFn         IamRepoFactory
		atRepoFn          AuthTokenRepoFactory
		am                *AuthMethod
		apiAddrs          string
		state             string
		code              string
		wantSubject       string
		wantInfoName      string
		wantInfoEmail     string
		wantFinalRedirect string
		wantErrMatch      *errors.Template
		wantErrContains   string
	}{
		{
			name:              "simple", // must remain the first test
			oidcRepoFn:        repoFn,
			iamRepoFn:         iamRepoFn,
			atRepoFn:          atRepoFn,
			am:                testAuthMethod,
			apiAddrs:          testController.URL,
			state:             testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:              "simple",
			wantFinalRedirect: "https://testcontroler.com/hi-alice",
			wantSubject:       "alice@example.com",
			wantInfoName:      "alice doe-eve",
			wantInfoEmail:     "alice@example.com",
		},
		{
			name:              "dup", // must follow "simple" unit test
			oidcRepoFn:        repoFn,
			iamRepoFn:         iamRepoFn,
			atRepoFn:          atRepoFn,
			am:                testAuthMethod,
			apiAddrs:          testController.URL,
			state:             testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:              "simple",
			wantFinalRedirect: "https://testcontroler.com/hi-alice",
			wantSubject:       "alice@example.com",
			wantInfoName:      "alice doe-eve",
			wantInfoEmail:     "alice@example.com",
		},
		{
			name:              "inactive-valid",
			setup:             setupFn,
			oidcRepoFn:        repoFn,
			iamRepoFn:         iamRepoFn,
			atRepoFn:          atRepoFn,
			am:                testAuthMethod2,
			apiAddrs:          testController.URL,
			state:             testState(t, testAuthMethod2, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash2, testNonce),
			code:              "simple",
			wantFinalRedirect: "https://testcontroler.com/hi-alice",
			wantSubject:       "alice@example.com",
			wantInfoName:      "alice doe-eve",
			wantInfoEmail:     "alice@example.com",
		},
		{
			name:            "missing-oidc-repo-fn",
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			apiAddrs:        testController.URL,
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
			apiAddrs:        testController.URL,
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
			apiAddrs:        testController.URL,
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
			apiAddrs:        testController.URL,
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
			apiAddrs:        testController.URL,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing code",
		},
		{
			name:            "missing-auth-method-id",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              func() *AuthMethod { am := AllocAuthMethod(); return &am }(),
			apiAddrs:        testController.URL,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.InvalidParameter),
			wantErrContains: "missing auth method",
		},
		{
			name:            "bad-auth-method-id",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              func() *AuthMethod { am := AllocAuthMethod(); am.PublicId = "not-valid"; return &am }(),
			apiAddrs:        testController.URL,
			state:           testState(t, testAuthMethod, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.RecordNotFound),
			wantErrContains: "auth method not-valid not found",
		},
		{
			name:            "bad-state-encoding",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			apiAddrs:        testController.URL,
			state:           "unable to decode message",
			code:            "simple",
			wantErrMatch:    errors.T(errors.Unknown),
			wantErrContains: "unable to decode message",
		},
		{
			name:            "unable-to-decrypt",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod,
			apiAddrs:        testController.URL,
			state:           testState(t, testAuthMethod2, kmsCache, testTokenRequestId, 2000*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce),
			code:            "simple",
			wantErrMatch:    errors.T(errors.Decrypt),
			wantErrContains: "unable to decrypt message",
		},
		{
			name:            "inactive-with-config-change",
			oidcRepoFn:      repoFn,
			iamRepoFn:       iamRepoFn,
			atRepoFn:        atRepoFn,
			am:              testAuthMethod2,
			apiAddrs:        testController.URL,
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
			apiAddrs:        testController.URL,
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
			excludeUsers := []interface{}{"u_anon", "u_auth", "u_recovery"}
			_, err = rw.Exec(ctx, "delete from iam_user where public_id not in(?, ?, ?)", excludeUsers)
			require.NoError(err)
			// start with no oplog entries
			_, err = rw.Exec(ctx, "delete from oplog_entry", nil)
			require.NoError(err)

			if tt.setup != nil {
				tt.setup()
			}

			tp.SetExpectedAuthNonce("nonce")
			if tt.am != nil {
				tp.SetClientCreds(tt.am.ClientId, tt.am.ClientSecret)
				tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, tt.apiAddrs, tt.am.PublicId)
				tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
			}

			if tt.code != "" {
				tp.SetExpectedAuthCode(tt.code)
			}
			if tt.state != "" {
				tp.SetExpectedState(tt.state)
			}
			info := map[string]string{}
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
				tt.apiAddrs,
				tt.am.PublicId,
				tt.state,
				tt.code,
			)
			if tt.wantErrMatch != nil {
				require.Error(err)
				assert.Empty(gotRedirect)
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch.Code, err)
				assert.Contains(err.Error(), tt.wantErrContains)

				// make sure there are no tokens in the db..
				var tokens []authtoken.AuthToken
				err := rw.SearchWhere(ctx, &tokens, "1=?", []interface{}{1})
				require.NoError(err)
				assert.Equal(0, len(tokens))

				var entries []oplog.Entry
				err = rw.SearchWhere(ctx, &entries, "1=?", []interface{}{1})
				require.NoError(err)
				require.Equalf(0, len(entries), "should not have found oplog entry for %s", tt.am.PublicId)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantFinalRedirect, gotRedirect)
			var tokens []authtoken.AuthToken
			err = rw.SearchWhere(ctx, &tokens, "1=?", []interface{}{1})
			require.NoError(err)
			require.Equal(1, len(tokens))
			tk, err := atRepo.LookupAuthToken(ctx, tokens[0].PublicId)
			require.NoError(err)
			assert.Equal(tk.Status, string(authtoken.PendingStatus))

			var acct Account
			err = rw.LookupWhere(ctx, &acct, "auth_method_id = ? and subject_id = ?", tt.am.PublicId, tt.wantSubject)
			require.NoError(err)
			assert.Equal(tt.wantInfoEmail, acct.Email)
			assert.Equal(tt.wantInfoName, acct.FullName)
			assert.Equal(tk.AuthAccountId, acct.PublicId)

			var users []iam.User
			err = rw.SearchWhere(ctx, &users, "public_id not in(?, ?, ?)", excludeUsers)
			require.NoError(err)
			require.Equal(1, len(users))
			assert.Equal(tk.IamUserId, users[0].PublicId)

			var entries []oplog.Entry
			err = rw.SearchWhere(ctx, &entries, "1=?", []interface{}{1})
			require.NoError(err)
			oplogWrapper, err := kmsCache.GetWrapper(ctx, tt.am.ScopeId, kms.KeyPurposeOplog)
			require.NoError(err)
			types, err := oplog.NewTypeCatalog(
				oplog.Type{Interface: new(store.Account), Name: "auth_oidc_account"},
				oplog.Type{Interface: new(iamStore.User), Name: "iam_user"},
				oplog.Type{Interface: new(authStore.Account), Name: "auth_account"},
			)
			require.NoError(err)

			cnt := 0
			foundAcct, foundOidcAcct := false, false
			for _, e := range entries {
				cnt += 1
				e.Cipherer = oplogWrapper
				err := e.DecryptData(ctx)
				require.NoError(err)
				msgs, err := e.UnmarshalData(types)
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
		assert, require := assert.New(t), require.New(t)

		// start with no tokens in the db
		_, err := rw.Exec(ctx, "delete from auth_token", nil)
		require.NoError(err)
		// start with no users in the db
		excludeUsers := []interface{}{"u_anon", "u_auth", "u_recovery"}
		_, err = rw.Exec(ctx, "delete from iam_user where public_id not in(?, ?, ?)", excludeUsers)
		require.NoError(err)
		// start with no oplog entries
		_, err = rw.Exec(ctx, "delete from oplog_entry", nil)
		require.NoError(err)
		tp.SetClientCreds(testAuthMethod.ClientId, testAuthMethod.ClientSecret)
		tpAllowedRedirect := fmt.Sprintf(CallbackEndpoint, testController.URL, testAuthMethod.PublicId)
		tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
		state := testState(t, testAuthMethod, kmsCache, testTokenRequestId, 20*time.Second, "https://testcontroler.com/hi-alice", testConfigHash, testNonce)
		tp.SetExpectedAuthCode("simple")
		tp.SetExpectedState(state)
		gotRedirect, err := Callback(ctx,
			repoFn,
			iamRepoFn,
			atRepoFn,
			testController.URL,
			testAuthMethod.PublicId,
			state,
			"simple",
		)
		require.NoError(err)
		require.NotNil(gotRedirect)

		gotRedirect2, err := Callback(ctx,
			repoFn,
			iamRepoFn,
			atRepoFn,
			testController.URL,
			testAuthMethod.PublicId,
			state,
			"simple",
		)
		require.Error(err)
		require.Empty(gotRedirect2)
		assert.Truef(errors.Match(errors.T(errors.Forbidden), err), "want err code: %q got: %q", errors.InvalidParameter, err)
		assert.Contains(err.Error(), "not a unique request")
	})
	t.Run("startAuth-to-Callback", func(t *testing.T) {
		// let's see if we can successfully test StartAuth(...) through Callback(...)
		assert, require := assert.New(t), require.New(t)

		// start with no tokens in the db
		_, err := rw.Exec(ctx, "delete from auth_token", nil)
		require.NoError(err)
		// start with no users in the db
		excludeUsers := []interface{}{"u_anon", "u_auth", "u_recovery"}
		_, err = rw.Exec(ctx, "delete from iam_user where public_id not in(?, ?, ?)", excludeUsers)
		require.NoError(err)
		// start with no oplog entries
		_, err = rw.Exec(ctx, "delete from oplog_entry", nil)
		require.NoError(err)

		controller := startControllerSrv(t, repoFn, iamRepoFn, atRepoFn)

		endToEndAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, ActivePublicState,
			TestConvertToUrls(t, tp.Addr())[0],
			"end-to-end-rp", "fido",
			WithCertificates(tpCert...),
			WithSigningAlgs(Alg(tpAlg)),
			WithCallbackUrls(TestConvertToUrls(t, controller.Addr())[0]))
		org, _ = iamRepo.LookupScope(ctx, org.PublicId) // need the updated org version, so we can set the primary auth method id
		require.NoError(err)
		iam.TestSetPrimaryAuthMethod(t, iamRepo, org, endToEndAuthMethod.PublicId)

		controller.SetAuthMethodId(endToEndAuthMethod.PublicId)

		tp.SetClientCreds(endToEndAuthMethod.ClientId, endToEndAuthMethod.ClientSecret)
		tpAllowedRedirect := controller.CallbackUrl()
		tp.SetAllowedRedirectURIs([]string{tpAllowedRedirect})
		authUrl, _, _, err := StartAuth(ctx, repoFn, controller.Addr(), endToEndAuthMethod.PublicId)
		require.NoError(err)

		authParams, err := url.ParseQuery(authUrl.RawQuery)
		require.NoError(err)
		require.Equal(1, len(authParams["nonce"]))
		require.Equal(1, len(authParams["state"]))
		tp.SetExpectedState(authParams["state"][0])
		tp.SetExpectedAuthNonce(authParams["nonce"][0])
		tp.SetExpectedAuthCode("simple")

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
		contents, err := ioutil.ReadAll(resp.Body)
		require.NoError(err)
		assert.Containsf(string(contents), "Congratulations", "expected \"Congratulations\" on successful oidc authentication and got: %s", string(contents))
	})
}
