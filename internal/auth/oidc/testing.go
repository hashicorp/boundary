// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/auth/oidc/request"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/cap/oidc"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const TestFakeManagedGroupFilter = `"/foo" == "bar"`

// TestAuthMethod creates a test oidc auth method.  WithName, WithDescription,
// WithMaxAge, WithApiUrl, WithIssuer, WithCertificates, WithAudClaims,
// WithSigningAlgs and WithPrompts options are supported.
func TestAuthMethod(
	t testing.TB,
	conn *db.DB,
	databaseWrapper wrapping.Wrapper,
	scopeId string,
	state AuthMethodState,
	clientId string,
	clientSecret ClientSecret,
	opt ...Option,
) *AuthMethod {
	t.Helper()
	ctx := context.TODO()
	opts := getOpts(opt...)
	require := require.New(t)
	rw := db.New(conn)

	authMethod, err := NewAuthMethod(ctx, scopeId, clientId, clientSecret, opt...)
	require.NoError(err)
	id, err := newAuthMethodId(ctx)
	require.NoError(err)
	authMethod.PublicId = id
	err = authMethod.encrypt(ctx, databaseWrapper)
	require.NoError(err)
	err = rw.Create(ctx, authMethod)
	require.NoError(err)

	if len(opts.withAudClaims) > 0 {
		newAudClaims := make([]*AudClaim, 0, len(opts.withAudClaims))
		for _, a := range opts.withAudClaims {
			aud, err := NewAudClaim(ctx, authMethod.PublicId, a)
			require.NoError(err)
			newAudClaims = append(newAudClaims, aud)
		}
		err := rw.CreateItems(ctx, newAudClaims)
		require.NoError(err)
		require.Equal(len(opts.withAudClaims), len(authMethod.AudClaims))
	}
	if len(opts.withCertificates) > 0 {
		newCerts := make([]*Certificate, 0, len(opts.withCertificates))
		for _, c := range opts.withCertificates {
			pem, err := EncodeCertificates(ctx, c)
			require.NoError(err)
			cert, err := NewCertificate(ctx, authMethod.PublicId, pem[0])
			require.NoError(err)
			newCerts = append(newCerts, cert)
		}
		err := rw.CreateItems(ctx, newCerts)
		require.NoError(err)
		require.Equal(len(opts.withCertificates), len(authMethod.Certificates))
	}
	if len(opts.withSigningAlgs) > 0 {
		newAlgs := make([]*SigningAlg, 0, len(opts.withSigningAlgs))
		for _, a := range opts.withSigningAlgs {
			alg, err := NewSigningAlg(ctx, authMethod.PublicId, a)
			require.NoError(err)
			newAlgs = append(newAlgs, alg)
		}
		err := rw.CreateItems(ctx, newAlgs)
		require.NoError(err)
		require.Equal(len(opts.withSigningAlgs), len(authMethod.SigningAlgs))
	}
	if len(opts.withClaimsScopes) > 0 {
		newClaimsScopes := make([]*ClaimsScope, 0, len(opts.withClaimsScopes))
		for _, cs := range opts.withClaimsScopes {
			s, err := NewClaimsScope(ctx, authMethod.PublicId, cs)
			require.NoError(err)
			newClaimsScopes = append(newClaimsScopes, s)
		}
		err := rw.CreateItems(ctx, newClaimsScopes)
		require.NoError(err)
		require.Equal(len(opts.withClaimsScopes), len(authMethod.ClaimsScopes))
	}
	if len(opts.withAccountClaimMap) > 0 {
		newAccountClaimMaps := make([]*AccountClaimMap, 0, len(opts.withAccountClaimMap))
		for k, v := range opts.withAccountClaimMap {
			acm, err := NewAccountClaimMap(ctx, authMethod.PublicId, k, v)
			require.NoError(err)
			newAccountClaimMaps = append(newAccountClaimMaps, acm)
		}
		require.NoError(rw.CreateItems(ctx, newAccountClaimMaps))
		require.Equal(len(opts.withAccountClaimMap), len(authMethod.AccountClaimMaps))
	}
	if len(opts.withPrompts) > 0 {
		newPrompts := make([]*Prompt, 0, len(opts.withPrompts))
		for _, p := range opts.withPrompts {
			prompt, err := NewPrompt(ctx, authMethod.PublicId, p)
			require.NoError(err)
			newPrompts = append(newPrompts, prompt)
		}
		err := rw.CreateItems(ctx, newPrompts)
		require.NoError(err)
		require.Equal(len(opts.withPrompts), len(authMethod.Prompts))
	}
	authMethod.OperationalState = string(state)
	rowsUpdated, err := rw.Update(ctx, authMethod, []string{OperationalStateField}, nil)
	require.NoError(err)
	require.True(rowsUpdated == 0 || rowsUpdated == 1)

	return authMethod
}

// TestSortAuthMethods will sort the provided auth methods by public id and it
// will sort each auth method's embedded value objects (algs, auds, certs,
// callbacks)
func TestSortAuthMethods(t testing.TB, methods []*AuthMethod) {
	// sort them by public id first...
	sort.Slice(methods, func(a, b int) bool {
		return methods[a].PublicId < methods[b].PublicId
	})

	// sort all the embedded value objects...
	for _, am := range methods {
		sort.Slice(am.SigningAlgs, func(a, b int) bool {
			return am.SigningAlgs[a] < am.SigningAlgs[b]
		})
		sort.Slice(am.AudClaims, func(a, b int) bool {
			return am.AudClaims[a] < am.AudClaims[b]
		})
		sort.Slice(am.Certificates, func(a, b int) bool {
			return am.Certificates[a] < am.Certificates[b]
		})
		sort.Slice(am.ClaimsScopes, func(a, b int) bool {
			return am.ClaimsScopes[a] < am.ClaimsScopes[b]
		})
		sort.Slice(am.AccountClaimMaps, func(a, b int) bool {
			return am.AccountClaimMaps[a] < am.AccountClaimMaps[b]
		})
	}
}

// TestAccount creates a test oidc auth account.
func TestAccount(t testing.TB, conn *db.DB, am *AuthMethod, subject string, opt ...Option) *Account {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	ctx := context.Background()

	u, err := url.Parse(am.GetIssuer())
	require.NoError(err)
	opt = append(opt, WithIssuer(u))
	a, err := NewAccount(ctx, am.PublicId, subject, opt...)
	require.NoError(err)

	id, err := newAccountId(ctx, am.GetPublicId(), am.Issuer, subject)
	require.NoError(err)
	a.PublicId = id

	require.NoError(rw.Create(ctx, a))
	return a
}

// TestAuthMethodWithAccountInManagedGroup creates an authMethod, and an account within that authmethod, an
// OIDC managed group, and add the newly created account as a member of the OIDC managed group.
func TestAuthMethodWithAccountInManagedGroup(t *testing.T, conn *db.DB, kmsCache *kms.Kms, scopeId string) (auth.AuthMethod, auth.Account, auth.ManagedGroup) {
	t.Helper()
	uuid, err := uuid.GenerateUUID()
	require.NoError(t, err)
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), scopeId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, scopeId, ActivePublicState,
		"alice-rp", "fido",
		WithIssuer(TestConvertToUrls(t, fmt.Sprintf("https://%s.com", uuid))[0]),
		WithSigningAlgs(Alg(oidc.RS256)),
		WithApiUrl(TestConvertToUrls(t, fmt.Sprintf("https://%s.com/callback", uuid))[0]))
	account := TestAccount(t, conn, testAuthMethod, "testacct")
	managedGroup := TestManagedGroup(t, conn, testAuthMethod, `"/token/sub" matches ".*"`)
	TestManagedGroupMember(t, conn, managedGroup.PublicId, account.PublicId)
	return testAuthMethod, account, managedGroup
}

// TestManagedGroup creates a test oidc managed group.
func TestManagedGroup(t testing.TB, conn *db.DB, am *AuthMethod, filter string, opt ...Option) *ManagedGroup {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	ctx := context.Background()

	mg, err := NewManagedGroup(ctx, am.PublicId, filter, opt...)
	require.NoError(err)

	id, err := newManagedGroupId(ctx)
	require.NoError(err)
	mg.PublicId = id

	require.NoError(rw.Create(ctx, mg))
	return mg
}

// TestManagedGroupMember adds given account IDs to a managed group
func TestManagedGroupMember(t testing.TB, conn *db.DB, managedGroupId, accountId string, opt ...Option) *ManagedGroupMemberAccount {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	ctx := context.Background()

	mg, err := NewManagedGroupMemberAccount(ctx, managedGroupId, accountId, opt...)
	require.NoError(err)

	require.NoError(rw.Create(ctx, mg))
	return mg
}

// TestConvertToUrls will convert URL string representations to a slice of
// *url.URL
func TestConvertToUrls(t testing.TB, urls ...string) []*url.URL {
	t.Helper()
	require := require.New(t)
	require.NotEmpty(urls)
	var convertedUrls []*url.URL
	for _, u := range urls {
		parsed, err := url.Parse(u)
		require.NoError(err)
		require.Contains([]string{"http", "https"}, parsed.Scheme)
		convertedUrls = append(convertedUrls, parsed)
	}
	return convertedUrls
}

// testGenerateCA will generate a test x509 CA cert, along with it encoded in a
// PEM format.
func testGenerateCA(t testing.TB, hosts ...string) (*x509.Certificate, string) {
	t.Helper()
	require := require.New(t)

	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(err)

	// ECDSA, ED25519 and RSA subject keys should have the DigitalSignature
	// KeyUsage bits set in the x509.Certificate template
	keyUsage := x509.KeyUsageDigitalSignature

	validFor := 2 * time.Minute
	notBefore := time.Now()
	notAfter := notBefore.Add(validFor)

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	require.NoError(err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Acme Co"},
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,

		KeyUsage:              keyUsage,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, h)
		}
	}

	template.IsCA = true
	template.KeyUsage |= x509.KeyUsageCertSign

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(err)

	c, err := x509.ParseCertificate(derBytes)
	require.NoError(err)

	return c, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes}))
}

func testProvider(t testing.TB, clientId, clientSecret, allowedRedirectURL string, tp *oidc.TestProvider) *oidc.Provider {
	t.Helper()
	require := require.New(t)
	require.NotEmptyf(clientId, "%s: client id is empty")
	require.NotEmptyf(clientSecret, "%s: client secret is empty")
	require.NotEmptyf(allowedRedirectURL, "%s: redirect URL is empty")

	tp.SetClientCreds(clientId, clientSecret)
	_, _, alg, _ := tp.SigningKeys()

	c1, err := oidc.NewConfig(
		tp.Addr(),
		clientId,
		oidc.ClientSecret(clientSecret),
		[]oidc.Alg{alg},
		[]string{allowedRedirectURL},
		oidc.WithProviderCA(tp.CACert()),
	)
	require.NoError(err)
	p1, err := oidc.NewProvider(c1)
	require.NoError(err)
	return p1
}

// testState will make a request.State and encrypt/encode within a request.Wrapper.
// the returned string can be used as a parameter for functions like: oidc.Callback
func testState(
	t testing.TB,
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
	createTime := timestamppb.New(now.Truncate(time.Second))
	exp := timestamppb.New(now.Add(expIn).Truncate(time.Second))

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

// TestTokenRequestId will make a request.Token and encrypt/encode within a request.Wrapper.
// the returned string can be used as a parameter for functions like: oidc.TokenRequest
func TestTokenRequestId(
	t testing.TB,
	am *AuthMethod,
	kms *kms.Kms,
	expIn time.Duration,
	tokenPublicId string,
) string {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)

	now := time.Now()
	exp := timestamppb.New(now.Add(expIn).Truncate(time.Second))

	reqTk := &request.Token{
		RequestId:      tokenPublicId,
		ExpirationTime: &timestamp.Timestamp{Timestamp: exp},
	}
	requestWrapper, err := requestWrappingWrapper(ctx, kms, am.ScopeId, am.PublicId)
	require.NoError(err)

	encodedEncryptedReqTk, err := encryptMessage(ctx, requestWrapper, am, reqTk)
	require.NoError(err)
	return encodedEncryptedReqTk
}

// TestPendingToken will create a pending auth token for the tokenRequestId (aka public id)
func TestPendingToken(
	t testing.TB,
	tokenRepo *authtoken.Repository,
	user *iam.User,
	acct *Account,
	tokenRequestId string,
) *authtoken.AuthToken {
	t.Helper()
	ctx := context.Background()
	require := require.New(t)
	tk, err := tokenRepo.CreateAuthToken(ctx, user, acct.PublicId, authtoken.WithPublicId(tokenRequestId), authtoken.WithStatus(authtoken.PendingStatus))
	require.NoError(err)
	return tk
}

// testControllerSrv is a test http server that supports the following
// endpoints:
//
// * /v1/auth-methods/<auth_method_id>:authenticate:callback
//
// * /authentication-complete
//
// * /authentication-error"
type testControllerSrv struct {
	mu sync.RWMutex

	authMethod *AuthMethod
	oidcRepoFn OidcRepoFactory
	iamRepoFn  IamRepoFactory
	atRepoFn   AuthTokenRepoFactory
	httpServer *httptest.Server
	t          testing.TB
}

// startTestControllerSrv returns a running testControllerSrv
func startTestControllerSrv(t testing.TB, oidcRepoFn OidcRepoFactory, iamRepoFn IamRepoFactory, atRepoFn AuthTokenRepoFactory) *testControllerSrv {
	require := require.New(t)
	require.NotNil(t)
	t.Helper()
	// the repo functions are allowed to be nil
	s := &testControllerSrv{
		t:          t,
		oidcRepoFn: oidcRepoFn,
		iamRepoFn:  iamRepoFn,
		atRepoFn:   atRepoFn,
	}
	s.httpServer = httptest.NewServer(s)
	s.httpServer.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.t.Cleanup(s.Stop)
	return s
}

// SetAuthMethod will set the auth method id used for various
// operations
func (s *testControllerSrv) SetAuthMethod(authMethod *AuthMethod) {
	s.t.Helper()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authMethod = authMethod
}

// AuthMethod returns the auth method id currently being used
// for various operations
func (s *testControllerSrv) AuthMethod() *AuthMethod {
	s.t.Helper()
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.authMethod
}

// Addr returns the scheme.host.port of the running srv.
func (s *testControllerSrv) Addr() string {
	s.t.Helper()
	return s.httpServer.URL
}

// FinalRedirectUrl returns the final redirect url for the srv,
// including scheme.host.port and path
func (s *testControllerSrv) FinalRedirectUrl() string {
	s.t.Helper()
	return fmt.Sprintf(FinalRedirectEndpoint, s.Addr())
}

// CallbackUrl returns the final callback url for the srv,
// including scheme.host.port and path
func (s *testControllerSrv) CallbackUrl() string {
	s.t.Helper()
	require := require.New(s.t)
	require.NotNil(s.authMethod, "auth method was missing")
	return fmt.Sprintf(CallbackEndpoint, s.Addr())
}

// ServeHTTP satisfies the http.Handler interface
func (s *testControllerSrv) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.t.Helper()
	require := require.New(s.t)
	switch req.URL.Path {
	case "/v1/auth-methods/oidc:authenticate:callback":
		err := req.ParseForm()
		require.NoErrorf(err, "%s: internal error: %w", "callback", err)
		state := req.FormValue("state")
		code := req.FormValue("code")
		error := req.FormValue("error")

		switch {
		case error != "":
			errorRedirectTo := fmt.Sprintf("%s/%s?error=%s", s.Addr(), AuthenticationErrorsEndpoint, error)
			s.t.Log("auth error: ", errorRedirectTo)
			http.RedirectHandler(errorRedirectTo, http.StatusMovedPermanently)
		default:
			redirectTo, err := Callback(context.Background(),
				s.oidcRepoFn,
				s.iamRepoFn,
				s.atRepoFn,
				s.authMethod,
				state,
				code,
			)
			if err != nil {
				errorRedirectTo := fmt.Sprintf("%s/%s?error=%s", s.Addr(), AuthenticationErrorsEndpoint, url.QueryEscape(err.Error()))
				s.t.Log("callback error: ", errorRedirectTo)
				http.RedirectHandler(errorRedirectTo, http.StatusFound)
				return
			}
			s.t.Log("callback success: ", redirectTo)
			http.Redirect(w, req, redirectTo, http.StatusFound)
			// http.RedirectHandler(redirectTo, 302)
		}
		return
	case "/authentication-complete":
		s.t.Log("authentication-complete")
		_, err := w.Write([]byte("Successful authentication. Congratulations!"))
		require.NoErrorf(err, "%s: internal error: %w", req.URL.Path, err)
		return
	case "/authentication-error":
		s.t.Log("authentication-error")
		err := req.ParseForm()
		require.NoErrorf(err, "%s: internal error: %w", "callback", err)
		error := req.FormValue("error")
		_, err = w.Write([]byte(fmt.Sprintf("authentication error: %s", error)))
		require.NoErrorf(err, "%s: internal error: %w", req.URL.Path, err)
	default:
		s.t.Log("path not found: ", req.URL.Path)
		w.WriteHeader(http.StatusNotFound)
		return
	}
}

// Stop stops the running testControllerSrv.  This is called as a test clean up function
// which is initialized when starting the srv
func (s *testControllerSrv) Stop() {
	s.t.Helper()
	s.httpServer.Close()
}
