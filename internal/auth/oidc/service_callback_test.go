package oidc

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/cap/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Callback(t *testing.T) {
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

	tests := []struct {
		name              string
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
			name:              "valid",
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
			name:              "dup",
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

			conn.LogMode(true)
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
				assert.Truef(errors.Match(tt.wantErrMatch, err), "want err code: %q got: %q", tt.wantErrMatch, err)
				assert.Contains(err.Error(), tt.wantErrContains)

				// make sure there are no tokens in the db..
				var tokens []authtoken.AuthToken
				err := rw.SearchWhere(ctx, &tokens, "1=?", []interface{}{1})
				require.NoError(err)
				assert.Equal(0, len(tokens))
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
		})
	}
}

// testState will make a request.State and encrypt/encode within a request.Wrapper.
// the returned string can be used as a parameter for functions like: oidc.Callback
func testState(
	t *testing.T,
	am *AuthMethod,
	kms *kms.Kms,
	tokenRequestId string,
	expIn time.Duration,
	finalRedirect string,
	providerHash uint64,
	nonce string,
) string {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	require.NotNil(am)
	require.NotNil(kms)

	now := time.Now()
	createTime, err := ptypes.TimestampProto(now.Truncate(time.Second))
	require.NoError(err)
	exp, err := ptypes.TimestampProto(now.Add(expIn).Truncate(time.Second))
	require.NoError(err)

	st := &request.State{
		TokenRequestId:     tokenRequestId,
		CreateTime:         &timestamp.Timestamp{Timestamp: createTime},
		ExpirationTime:     &timestamp.Timestamp{Timestamp: exp},
		FinalRedirectUrl:   finalRedirect,
		Nonce:              nonce,
		ProviderConfigHash: providerHash,
	}
	requestWrapper, err := requestWrappingWrapper(ctx, kms, am.ScopeId, am.PublicId)
	require.NoError(err)
	encodedEncryptedSt, err := encryptMessage(ctx, requestWrapper, am, st)
	require.NoError(err)
	return encodedEncryptedSt
}

type testCallbackSrv struct {
	oidcRepoFn OidcRepoFactory
	iamRepoFn  IamRepoFactory
	atRepoFn   AuthTokenRepoFactory
	httpServer *httptest.Server
	t          *testing.T
}

func startTestCallbackSrv(t *testing.T, oidcRepoFn OidcRepoFactory, iamRepoFn IamRepoFactory, atRepoFn AuthTokenRepoFactory) *testCallbackSrv {
	require := require.New(t)
	require.NotNil(t)
	t.Helper()
	// the repo functions are allowed to be nil
	s := &testCallbackSrv{
		t:          t,
		oidcRepoFn: oidcRepoFn,
		iamRepoFn:  iamRepoFn,
		atRepoFn:   atRepoFn,
	}
	s.httpServer = httptest.NewServer(s)
	s.httpServer.Config.ErrorLog = log.New(ioutil.Discard, "", 0)
	s.httpServer.Start()
	s.t.Cleanup(s.Stop)
	return s
}
func (s *testCallbackSrv) ServeHTTP(w http.ResponseWriter, req *http.Request) {
}

// Stop stops the running testCallbackSrv.
func (s *testCallbackSrv) Stop() {
	s.httpServer.Close()
}
