package vault

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/go-rootcerts"
	vault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type clientConfig struct {
	Addr          string
	Token         TokenSecret
	CaCert        []byte
	ClientCert    []byte
	ClientKey     KeySecret
	TlsServerName string
	TlsSkipVerify bool
	Namespace     string
}

func (c *clientConfig) isValid() bool {
	if c == nil || c.Addr == "" || len(c.Token) < 0 {
		return false
	}
	return true
}

func (c *clientConfig) isClientTLS() bool {
	if len(c.ClientCert) > 0 && len(c.ClientKey) > 0 {
		return true
	}
	return false
}

type client struct {
	cl    *vault.Client
	token TokenSecret
}

func newClient(c *clientConfig) (*client, error) {
	const op = "vault.newClient"
	if !c.isValid() {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "invalid configuration")
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
			return nil, errors.WrapDeprecated(err, op)
		}
	}

	if c.isClientTLS() {
		clientCert, err := tls.X509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, errors.WrapDeprecated(err, op)
		}
		tlsConfig := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	vClient, err := vault.NewClient(vc)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op)
	}
	vClient.SetToken(string(c.Token))

	return &client{
		cl:    vClient,
		token: c.Token,
	}, nil
}

// ping calls the /sys/health Vault endpoint and returns an error if no
// response is returned. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/health#read-health-information.
func (c *client) ping() error {
	const op = "vault.(client).ping"
	h, err := c.cl.Sys().Health()
	switch {
	case err != nil:
		return errors.WrapDeprecated(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	case h == nil:
		return errors.NewDeprecated(errors.Unavailable, op, fmt.Sprintf("no repsonse: vault: %s", c.cl.Address()))
	case !h.Initialized || h.Sealed:
		return errors.NewDeprecated(errors.Unavailable, op, fmt.Sprintf("vault (%s): initialized: %t, sealed: %t ", c.cl.Address(), h.Initialized, h.Sealed))
	}

	return nil
}

// renewToken calls the /auth/token/renew-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/auth/token#renew-a-token-self.
func (c *client) renewToken() (*vault.Secret, error) {
	const op = "vault.(client).renewToken"
	t, err := c.cl.Auth().Token().RenewSelf(0)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

// revokeToken calls the /auth/token/revoke-self Vault endpoint. This
// endpoint is accessible with the default policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/auth/token#revoke-a-token-self.
func (c *client) revokeToken() error {
	const op = "vault.(client).revokeToken"
	// The `token` parameter is kept for backwards compatibility but is ignored, so use ""
	if err := c.cl.Auth().Token().RevokeSelf(""); err != nil {
		return errors.WrapDeprecated(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return nil
}

// renewLease calls the /sys/leases/renew Vault endpoint and returns the
// vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/leases#renew-lease.
func (c *client) renewLease(leaseId string, leaseDuration time.Duration) (*vault.Secret, error) {
	const op = "vault.(client).renewLease"
	t, err := c.cl.Sys().Renew(leaseId, int(leaseDuration.Round(time.Second).Seconds()))
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithCode(errors.VaultCredentialRequest), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

// revokeLease calls the /sys/leases/revoke Vault endpoint. This endpoint
// is NOT accessible with the default policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/leases#revoke-lease.
func (c *client) revokeLease(leaseId string) error {
	const op = "vault.(client).revokeLease"
	if err := c.cl.Sys().Revoke(leaseId); err != nil {
		return errors.WrapDeprecated(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return nil
}

// lookupToken calls the /auth/token/lookup-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/auth/token#lookup-a-token-self.
func (c *client) lookupToken() (*vault.Secret, error) {
	const op = "vault.(client).lookupToken"
	t, err := c.cl.Auth().Token().LookupSelf()
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

// swapToken replaces the token in the Vault client with t and returns the
// token that was replaced.
func (c *client) swapToken(new TokenSecret) (old TokenSecret) {
	old = TokenSecret(c.cl.Token())
	c.cl.SetToken(string(new))
	return
}

func (c *client) get(path string) (*vault.Secret, error) {
	const op = "vault.(client).get"
	s, err := c.cl.Logical().Read(path)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithCode(errors.VaultCredentialRequest), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return s, nil
}

func (c *client) post(path string, data []byte) (*vault.Secret, error) {
	const op = "vault.(client).post"

	if len(data) == 0 {
		// For POST and PUT methods, Vault requires a valid JSON object be
		// sent even if the JSON object is empty
		data = []byte(`{}`)
	}
	s, err := c.cl.Logical().WriteBytes(path, data)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithCode(errors.VaultCredentialRequest), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return s, nil
}

// capabilities calls the /sys/capabilities-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/capabilities-self.
func (c *client) capabilities(paths []string) (pathCapabilities, error) {
	const op = "vault.(client).capabilities"
	if len(paths) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "empty paths")
	}
	body := map[string]string{
		"paths": strings.Join(paths, ","),
	}
	reqPath := "/v1/sys/capabilities-self"

	r := c.cl.NewRequest("POST", reqPath)
	if err := r.SetJSONBody(body); err != nil {
		return nil, err
	}

	ctx, cancelFunc := context.WithCancel(context.Background())
	defer cancelFunc()
	resp, err := c.cl.RawRequestWithContext(ctx, r)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	secret, err := vault.ParseSecret(resp.Body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.NewDeprecated(errors.Unknown, op, "data from Vault is empty")
	}

	var res map[string][]string
	if err := mapstructure.Decode(secret.Data, &res); err != nil {
		return nil, err
	}

	return newPathCapabilities(res), nil
}
