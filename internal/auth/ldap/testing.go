package ldap

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
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/stretchr/testify/require"
)

const testInvalidPem = `-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
-----END CERTIFICATE-----`

func TestAuthMethod(t testing.TB,
	conn *db.DB,
	databaseWrapper wrapping.Wrapper,
	scopeId string,
	urls []string,
	opt ...Option,
) *AuthMethod {
	t.Helper()
	require.Greater(t, len(urls), 0)
	testCtx := context.TODO()
	require := require.New(t)
	rw := db.New(conn)

	opts, err := getOpts(opt...)
	require.NoError(err)
	am, err := NewAuthMethod(testCtx, scopeId, TestConvertToUrls(t, urls...), opt...)
	require.NoError(err)
	id, err := newAuthMethodId(testCtx)
	require.NoError(err)
	am.PublicId = id
	_, err = rw.DoTx(testCtx, 0, db.ConstBackoff{}, func(r db.Reader, w db.Writer) error {
		if err := w.Create(testCtx, am); err != nil {
			return err
		}
		for priority, u := range urls {
			storeUrl, err := NewUrl(testCtx, am.PublicId, priority, TestConvertToUrls(t, u)[0])
			if err != nil {
				return err
			}
			if err := w.Create(testCtx, storeUrl); err != nil {
				return err
			}
		}
		if len(opts.withCertificates) > 0 {
			for _, pem := range opts.withCertificates {
				c, err := NewCertificate(testCtx, am.PublicId, pem)
				if err != nil {
					return err
				}
				if err := w.Create(testCtx, c); err != nil {
					return err
				}
			}
		}
		if opts.withUserDn != "" || opts.withUserAttr != "" || opts.withUserFilter != "" {
			uc, err := NewUserEntrySearchConf(testCtx, am.PublicId, opt...)
			if err != nil {
				return err
			}
			if err = w.Create(testCtx, uc); err != nil {
				return err
			}
		}
		if opts.withGroupDn != "" || opts.withGroupAttr != "" || opts.withGroupFilter != "" {
			uc, err := NewGroupEntrySearchConf(testCtx, am.PublicId, opt...)
			if err != nil {
				return err
			}
			if err = w.Create(testCtx, uc); err != nil {
				return err
			}
		}
		if opts.withClientCertificate != "" || len(opts.withClientCertificateKey) != 0 {
			cc, err := NewClientCertificate(testCtx, am.PublicId, opts.withClientCertificateKey, opts.withClientCertificate)
			if err != nil {
				return err
			}
			if err := cc.encrypt(testCtx, databaseWrapper); err != nil {
				return err
			}
			if err := w.Create(testCtx, cc); err != nil {
				return err
			}
			am.ClientCertificateKeyHmac = cc.CertificateKeyHmac
		}
		if opts.withBindDn != "" || opts.withBindPassword != "" {
			bc, err := NewBindCredential(testCtx, am.PublicId, opts.withBindDn, []byte(opts.withBindPassword))
			if err != nil {
				return err
			}
			if err := bc.encrypt(testCtx, databaseWrapper); err != nil {
				return err
			}
			if err := w.Create(testCtx, bc); err != nil {
				return err
			}
			am.BindPasswordHmac = bc.PasswordHmac
		}
		return nil
	})
	require.NoError(err)

	return am
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
		require.Contains([]string{"ldap", "ldaps"}, parsed.Scheme)
		convertedUrls = append(convertedUrls, parsed)
	}
	return convertedUrls
}

// TestSortAuthMethods will sort the provided auth methods by public id and it
// will sort each auth method's embedded value objects
func TestSortAuthMethods(t testing.TB, methods []*AuthMethod) {
	// sort them by public id first...
	sort.Slice(methods, func(a, b int) bool {
		return methods[a].PublicId < methods[b].PublicId
	})

	// sort all the embedded value objects...
	for _, am := range methods {
		sort.Slice(am.Urls, func(a, b int) bool {
			return am.Urls[a] < am.Urls[b]
		})
		sort.Slice(am.Certificates, func(a, b int) bool {
			return am.Certificates[a] < am.Certificates[b]
		})
	}
}
