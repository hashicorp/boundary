// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package ldap

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"sort"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/auth"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-secure-stdlib/parseutil"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/require"
)

const TestInvalidPem = `-----BEGIN CERTIFICATE-----
MIICUTCCAfugAwIBAgIBADANBgkqhkiG9w0BAQQFADBXMQswCQYDVQQGEwJDTjEL
-----END CERTIFICATE-----`

var testGrpNames = []string{"test-admin", "test-users"}

// TestEncodeGrpNames will json marshal group names
func TestEncodedGrpNames(t *testing.T, names ...string) string {
	encoded, err := json.Marshal(names)
	require.NoError(t, err)
	return string(encoded)
}

// TestAuthMethod creates a new auth method and it's persisted in the database.
// See NewAuthMethod for list of supported options.
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

	opt = append(opt, WithUrls(testCtx, TestConvertToUrls(t, urls...)...))

	opts, err := getOpts(opt...)
	require.NoError(err)
	am, err := NewAuthMethod(testCtx, scopeId, opt...)
	require.NoError(err)
	id, err := newAuthMethodId(testCtx)
	require.NoError(err)
	am.PublicId = id
	_, err = rw.DoTx(testCtx, 0, db.ConstBackoff{}, func(r db.Reader, w db.Writer) error {
		if err := w.Create(testCtx, am); err != nil {
			return err
		}
		for priority, u := range urls {
			storeUrl, err := NewUrl(testCtx, am.PublicId, priority+1, TestConvertToUrls(t, u)[0])
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
		if len(opts.withAccountAttributeMap) > 0 {
			for from, to := range opts.withAccountAttributeMap {
				aam, err := NewAccountAttributeMap(testCtx, am.PublicId, from, AccountToAttribute(string(to)))
				if err != nil {
					return err
				}
				if err := w.Create(testCtx, aam); err != nil {
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
		if opts.withDerefAliases != "" {
			d, err := NewDerefAliases(testCtx, am.PublicId, opts.withDerefAliases)
			if err != nil {
				return err
			}
			if err := w.Create(testCtx, d); err != nil {
				return err
			}
			am.DereferenceAliases = d.DereferenceAliases
		}
		return nil
	})
	require.NoError(err)

	return am
}

// TestAccount creates a test ldap auth account.
func TestAccount(t testing.TB, conn *db.DB, am *AuthMethod, loginName string, opt ...Option) *Account {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	ctx := context.Background()

	a, err := NewAccount(ctx, am.ScopeId, am.PublicId, loginName, opt...)
	require.NoError(err)

	id, err := newAccountId(ctx, am.PublicId, loginName)
	require.NoError(err)
	a.PublicId = id

	require.NoError(rw.Create(ctx, a))
	return a
}

// TestAuthMethodWithAccountInManagedGroup creates an authMethod, and an account within that authmethod, an
// LDAP managed group, and add the newly created account as a member of the LDAP managed group.
func TestAuthMethodWithAccountInManagedGroup(t *testing.T, conn *db.DB, kmsCache *kms.Kms, scopeId string) (auth.AuthMethod, auth.Account, auth.ManagedGroup) {
	t.Helper()
	uuid, err := uuid.GenerateUUID()
	require.NoError(t, err)
	ctx := context.Background()
	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), scopeId, kms.KeyPurposeDatabase)
	require.NoError(t, err)
	am := TestAuthMethod(t, conn, databaseWrapper, scopeId, []string{fmt.Sprintf("ldap://%s", uuid)})
	managedGroup := TestManagedGroup(t, conn, am, []string{uuid})
	acct := TestAccount(t, conn, am, "testacct", WithMemberOfGroups(ctx, uuid))
	return am, acct, managedGroup
}

// TestManagedGroup creates a test ldap managed group.
func TestManagedGroup(t testing.TB, conn *db.DB, am *AuthMethod, grpNames []string, opt ...Option) *ManagedGroup {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	ctx := context.Background()

	mg, err := NewManagedGroup(ctx, am.PublicId, grpNames, opt...)
	require.NoError(err)

	id, err := newManagedGroupId(ctx)
	require.NoError(err)
	mg.PublicId = id

	require.NoError(rw.Create(ctx, mg, db.WithLookup(true)))
	return mg
}

// TestGenerateCA will generate a test x509 CA cert, along with it encoded in a
// PEM format.
func TestGenerateCA(t testing.TB, hosts ...string) (*x509.Certificate, string) {
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
		var err error
		u, err = parseutil.NormalizeAddr(u)
		require.NoError(err)
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
		sort.Slice(am.AccountAttributeMaps, func(a, b int) bool {
			return am.AccountAttributeMaps[a] < am.AccountAttributeMaps[b]
		})
	}
}

// TestGetAcctManagedGroups will retrieve the managed groups associated with an account.
func TestGetAcctManagedGroups(t testing.TB, conn *db.DB, acctId string) []string {
	t.Helper()
	testCtx := context.Background()
	rw := db.New(conn)
	var memberAccts []*grpMemberAccts
	require.NoError(t, rw.SearchWhere(testCtx, &memberAccts, "member_id = ?", []any{acctId}))
	grpIds := make([]string, 0, len(memberAccts))
	for _, mbrAcct := range memberAccts {
		grpIds = append(grpIds, mbrAcct.ManagedGroupId)
	}
	return grpIds
}

type grpMemberAccts struct {
	CreateTime       time.Time
	MemberId         string
	ManagedGroupId   string
	ManagedGroupName string
}

func (*grpMemberAccts) TableName() string {
	return "auth_ldap_managed_group_member_account"
}
