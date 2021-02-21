package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/cap/oidc"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

// TestAuthMethod creates a test oidc auth method.  WithName, WithDescription,
// WithMaxAge, WithCallbackUrls, WithCertificates, WithAudClaims, and
// WithSigningAlgs options are supported.
func TestAuthMethod(
	t *testing.T,
	conn *gorm.DB,
	databaseWrapper wrapping.Wrapper,
	scopeId string,
	state AuthMethodState,
	discoveryUrl *url.URL,
	clientId string,
	clientSecret ClientSecret,
	opt ...Option) *AuthMethod {
	t.Helper()
	opts := getOpts(opt...)
	require := require.New(t)
	rw := db.New(conn)
	ctx := context.Background()

	authMethod, err := NewAuthMethod(scopeId, discoveryUrl, clientId, clientSecret, opt...)
	authMethod.OperationalState = string(state)
	require.NoError(err)
	id, err := newAuthMethodId()
	require.NoError(err)
	authMethod.PublicId = id
	err = authMethod.encrypt(ctx, databaseWrapper)
	require.NoError(err)
	err = rw.Create(ctx, authMethod)
	require.NoError(err)

	if len(opts.withCallbackUrls) > 0 {
		newCallbacks := make([]interface{}, 0, len(opts.withCallbackUrls))
		for _, c := range opts.withCallbackUrls {
			callback, err := NewCallbackUrl(authMethod.PublicId, c)
			require.NoError(err)
			newCallbacks = append(newCallbacks, callback)
		}
		err := rw.CreateItems(ctx, newCallbacks)
		require.NoError(err)
		require.Equal(len(opts.withCallbackUrls), len(authMethod.CallbackUrls))
	}
	if len(opts.withAudClaims) > 0 {
		newAudClaims := make([]interface{}, 0, len(opts.withAudClaims))
		for _, a := range opts.withAudClaims {
			aud, err := NewAudClaim(authMethod.PublicId, a)
			require.NoError(err)
			newAudClaims = append(newAudClaims, aud)
		}
		err := rw.CreateItems(ctx, newAudClaims)
		require.NoError(err)
		require.Equal(len(opts.withAudClaims), len(authMethod.AudClaims))
	}
	if len(opts.withCertificates) > 0 {
		newCerts := make([]interface{}, 0, len(opts.withCertificates))
		for _, c := range opts.withCertificates {
			pem, err := EncodeCertificates(c)
			require.NoError(err)
			cert, err := NewCertificate(authMethod.PublicId, pem[0])
			require.NoError(err)
			newCerts = append(newCerts, cert)
		}
		err := rw.CreateItems(ctx, newCerts)
		require.NoError(err)
		require.Equal(len(opts.withCertificates), len(authMethod.Certificates))
	}
	if len(opts.withSigningAlgs) > 0 {
		newAlgs := make([]interface{}, 0, len(opts.withSigningAlgs))
		for _, a := range opts.withSigningAlgs {
			alg, err := NewSigningAlg(authMethod.PublicId, a)
			require.NoError(err)
			newAlgs = append(newAlgs, alg)
		}
		err := rw.CreateItems(ctx, newAlgs)
		require.NoError(err)
		require.Equal(len(opts.withSigningAlgs), len(authMethod.SigningAlgs))
	}
	return authMethod
}

// TestSortAuthMethods will sort the provided auth methods by public id and it
// will sort each auth method's embedded value objects (algs, auds, certs,
// callbacks)
func TestSortAuthMethods(t *testing.T, methods []*AuthMethod) {
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
		sort.Slice(am.CallbackUrls, func(a, b int) bool {
			return am.AudClaims[a] < am.AudClaims[b]
		})
		sort.Slice(am.Certificates, func(a, b int) bool {
			return am.Certificates[a] < am.Certificates[b]
		})
	}
}

// TestAccount creates a test oidc auth account.
func TestAccount(t *testing.T, conn *gorm.DB, authMethodId string, issuerId *url.URL, subjectId string, opt ...Option) *Account {
	require := require.New(t)
	rw := db.New(conn)
	ctx := context.Background()

	a, err := NewAccount(authMethodId, issuerId, subjectId, opt...)
	require.NoError(err)

	id, err := newAccountId()
	require.NoError(err)
	a.PublicId = id

	require.NoError(rw.Create(ctx, a))
	return a
}

// TestConvertToUrls will convert URL string representations to a slice of
// *url.URL
func TestConvertToUrls(t *testing.T, urls ...string) []*url.URL {
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
func testGenerateCA(t *testing.T, hosts ...string) (*x509.Certificate, string) {
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

func testProvider(t *testing.T, clientId, clientSecret, allowedRedirectURL string, tp *oidc.TestProvider) *oidc.Provider {
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
