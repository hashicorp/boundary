package vault

import (
	"crypto/tls"
	"fmt"
	"net/http"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-rootcerts"
	vault "github.com/hashicorp/vault/api"
)

type clientConfig struct {
	Addr                  string
	Token                 string
	CaCert                []byte
	ClientCert, ClientKey []byte
	TlsServerName         string
	TlsSkipVerify         bool
	Namespace             string
}

func (c *clientConfig) IsValid() bool {
	if c == nil || c.Addr == "" || c.Token == "" {
		return false
	}
	return true
}

func (c *clientConfig) IsClientTLS() bool {
	if len(c.ClientCert) > 0 && len(c.ClientKey) > 0 {
		return true
	}
	return false
}

type client struct {
	cl    *vault.Client
	token string
}

func newClient(c *clientConfig) (*client, error) {
	const op = "vault.newClient"
	if !c.IsValid() {
		return nil, errors.New(errors.InvalidParameter, op, "invalid configuration")
	}
	vc := vault.DefaultConfig()
	vc.Address = c.Addr
	if len(c.CaCert) > 0 {
		rootConfig := &rootcerts.Config{
			CACertificate: c.CaCert,
		}
		tlsConfig := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
		tlsConfig.InsecureSkipVerify = c.TlsSkipVerify
		if err := rootcerts.ConfigureTLS(tlsConfig, rootConfig); err != nil {
			return nil, errors.Wrap(err, op)
		}
	}

	if c.IsClientTLS() {
		clientCert, err := tls.X509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, errors.Wrap(err, op)
		}
		tlsConfig := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	vClient, err := vault.NewClient(vc)
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	vClient.SetToken(c.Token)

	return &client{
		cl:    vClient,
		token: c.Token,
	}, nil
}

// Ping calls the /sys/health Vault endpoint and returns an error if no
// response is returned. This endpoint is accessible with the default
// policy in Vault 1.7.0. See
// https://www.vaultproject.io/api-docs/system/health#read-health-information.
func (c *client) Ping() error {
	const op = "vault.(client).Ping"
	h, err := c.cl.Sys().Health()
	switch {
	case err != nil:
		return errors.Wrap(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	case h == nil:
		return errors.New(errors.Unavailable, op, fmt.Sprintf("vault: %s", c.cl.Address()))
	default:
		return nil
	}
}

// RenewToken calls the /auth/token/renew-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.0. See
// https://www.vaultproject.io/api-docs/auth/token#renew-a-token-self.
func (c *client) RenewToken() (*vault.Secret, error) {
	const op = "vault.(client).RenewToken"
	t, err := c.cl.Auth().Token().RenewSelf(0)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

// LookupToken calls the /auth/token/lookup-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.0. See
// https://www.vaultproject.io/api-docs/auth/token#lookup-a-token-self.
func (c *client) LookupToken() (*vault.Secret, error) {
	const op = "vault.(client).LookupToken"
	t, err := c.cl.Auth().Token().LookupSelf()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

// SwapToken replaces the token in the Vault client with t and returns the
// token that was replaced.
func (c *client) SwapToken(t string) string {
	old := c.cl.Token()
	c.cl.SetToken(t)
	return old
}
