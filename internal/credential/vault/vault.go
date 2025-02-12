// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/event"
	"github.com/hashicorp/go-rootcerts"
	vault "github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

type vaultClient interface {
	ping(context.Context) error
	renewToken(context.Context) (*vault.Secret, error)
	revokeToken(context.Context) error
	renewLease(context.Context, string, time.Duration) (*vault.Secret, error)
	revokeLease(context.Context, string) error
	lookupToken(context.Context) (*vault.Secret, error)
	lookupWrappedToken(context.Context, string) (*wrappingLookupResponse, error)
	swapToken(context.Context, TokenSecret) (old TokenSecret)
	get(context.Context, string) (*vault.Secret, error)
	post(context.Context, string, []byte) (*vault.Secret, error)
	capabilities(context.Context, []string) (pathCapabilities, error)
	headers(ctx context.Context) (http.Header, error)
	unwrap(context.Context, string) (*vault.Secret, error)
}

var vaultClientFactoryFn = vaultClientFactory

func vaultClientFactory(ctx context.Context, c *clientConfig, opt ...Option) (vaultClient, error) {
	const op = "vault.vaultClientFactory"
	nc, err := newClient(ctx, c)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	return nc, nil
}

type clientConfig struct {
	Addr          string `json:"addr"`
	Token         []byte `json:"token"`
	CaCert        []byte `json:"ca_cert"`
	ClientCert    []byte `json:"client_cert"`
	ClientKey     []byte `json:"client_key"`
	TlsServerName string `json:"tls_server_name"`
	TlsSkipVerify bool   `json:"tls_skip_verify"`
	Namespace     string `json:"namespace"`
}

func (c *clientConfig) isValid() bool {
	if c == nil || c.Addr == "" || len(c.Token) == 0 {
		return false
	}
	return true
}

var _ vaultClient = (*client)(nil)

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

func newClient(ctx context.Context, c *clientConfig) (*client, error) {
	const op = "vault.newClient"
	if !c.isValid() {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "invalid configuration")
	}
	vc := vault.DefaultConfig()
	vc.Address = c.Addr
	tlsConfig := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
	tlsConfig.InsecureSkipVerify = c.TlsSkipVerify
	if c.TlsServerName != "" {
		tlsConfig.ServerName = c.TlsServerName
	}

	if len(c.CaCert) > 0 {
		rootConfig := &rootcerts.Config{
			CACertificate: c.CaCert,
		}
		if err := rootcerts.ConfigureTLS(tlsConfig, rootConfig); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	if c.isClientTLS() {
		clientCert, err := tls.X509KeyPair(c.ClientCert, c.ClientKey)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		tlsConfig := vc.HttpClient.Transport.(*http.Transport).TLSClientConfig
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return &clientCert, nil
		}
	}

	vClient, err := vault.NewClient(vc)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	vClient.SetToken(string(c.Token))

	if c.Namespace != "" {
		vClient.SetNamespace(c.Namespace)
	}

	if correlationId, ok := event.CorrelationIdFromContext(ctx); ok {
		vClient.AddHeader(globals.CorrelationIdKey, correlationId)
	}

	return &client{
		cl:    vClient,
		token: c.Token,
	}, nil
}

// ping calls the /sys/health Vault endpoint and returns an error if no
// response is returned. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/health#read-health-information.
func (c *client) ping(ctx context.Context) error {
	const op = "vault.(client).ping"
	h, err := c.cl.Sys().Health()
	switch {
	case err != nil:
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	case h == nil:
		return errors.New(ctx, errors.Unavailable, op, fmt.Sprintf("no response: vault: %s", c.cl.Address()))
	case !h.Initialized || h.Sealed:
		return errors.New(ctx, errors.Unavailable, op, fmt.Sprintf("vault (%s): initialized: %t, sealed: %t ", c.cl.Address(), h.Initialized, h.Sealed))
	}

	return nil
}

// renewToken calls the /auth/token/renew-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/auth/token#renew-a-token-self.
func (c *client) renewToken(ctx context.Context) (*vault.Secret, error) {
	const op = "vault.(client).renewToken"
	t, err := c.cl.Auth().Token().RenewSelf(0)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

// revokeToken calls the /auth/token/revoke-self Vault endpoint. This
// endpoint is accessible with the default policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/auth/token#revoke-a-token-self.
func (c *client) revokeToken(ctx context.Context) error {
	const op = "vault.(client).revokeToken"
	// The `token` parameter is kept for backwards compatibility but is ignored, so use ""
	if err := c.cl.Auth().Token().RevokeSelf(""); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return nil
}

// renewLease calls the /sys/leases/renew Vault endpoint and returns the
// vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/leases#renew-lease.
func (c *client) renewLease(ctx context.Context, leaseId string, leaseDuration time.Duration) (*vault.Secret, error) {
	const op = "vault.(client).renewLease"
	t, err := c.cl.Sys().Renew(leaseId, int(leaseDuration.Round(time.Second).Seconds()))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.VaultCredentialRequest), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

// revokeLease calls the /sys/leases/revoke Vault endpoint. This endpoint
// is NOT accessible with the default policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/leases#revoke-lease.
func (c *client) revokeLease(ctx context.Context, leaseId string) error {
	const op = "vault.(client).revokeLease"
	if err := c.cl.Sys().Revoke(leaseId); err != nil {
		return errors.Wrap(ctx, err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return nil
}

// lookupToken calls the /auth/token/lookup-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/auth/token#lookup-a-token-self.
func (c *client) lookupToken(ctx context.Context) (*vault.Secret, error) {
	const op = "vault.(client).lookupToken"
	t, err := c.cl.Auth().Token().LookupSelf()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.Unknown), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return t, nil
}

type wrappingLookupRequest struct {
	Token string `json:"token"`
}

// https://developer.hashicorp.com/vault/api-docs/system/wrapping-lookup#sample-response
type wrappingLookupResponse struct {
	CreationPath string
	CreationTime time.Time
	CreationTTL  int
}

func (wlr *wrappingLookupResponse) decodeData(data map[string]interface{}) error {
	const CreationPathKey = "creation_path"
	if path, ok := data[CreationPathKey].(string); ok {
		wlr.CreationPath = path
	} else {
		return fmt.Errorf("vault wrapping lookup response missing data key: %q", CreationPathKey)
	}

	const CreationTimeKey = "creation_time"
	if ctime, ok := data[CreationTimeKey].(string); ok {
		var err error = nil
		if wlr.CreationTime, err = time.Parse(time.RFC3339, ctime); err != nil {
			return fmt.Errorf("vault wrapping lookup response unable to parse data key: %q", CreationTimeKey)
		}
	} else {
		return fmt.Errorf("vault wrapping lookup response missing data key: %q", CreationTimeKey)
	}

	const CreationTTLKey = "creation_ttl"
	if ttl, ok := data[CreationTTLKey].(json.Number); ok {
		ttl64, err := ttl.Int64()
		if err != nil {
			return fmt.Errorf("vault wrapping lookup response unable to parse data key: %q", CreationTTLKey)
		}
		wlr.CreationTTL = int(ttl64)
	} else {
		return fmt.Errorf("vault wrapping lookup response missing data key: %q", CreationTTLKey)
	}

	return nil
}

// lookupWrappedToken calls the /sys/wrapping/lookup Vault endpoint and returns
// the token info. This endpoint is useful as it is unauthenticated and can always
// be accessed with the token itself as authentication. See
// https://developer.hashicorp.com/vault/docs/concepts/response-wrapping#response-wrapping-token-operations
func (c *client) lookupWrappedToken(ctx context.Context, wrappedToken string) (*wrappingLookupResponse, error) {
	const op = "vault.(client).lookupWrappedToken"
	const wrappingLookupPath = "sys/wrapping/lookup"

	payload := wrappingLookupRequest{
		Token: wrappedToken,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	res, err := c.post(ctx, wrappingLookupPath, body)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	wlr := &wrappingLookupResponse{}
	if err := wlr.decodeData(res.Data); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return wlr, nil
}

// swapToken replaces the token in the Vault client with t and returns the
// token that was replaced.
func (c *client) swapToken(ctx context.Context, new TokenSecret) (old TokenSecret) {
	old = TokenSecret(c.cl.Token())
	c.cl.SetToken(string(new))
	return
}

func (c *client) get(ctx context.Context, path string) (*vault.Secret, error) {
	const op = "vault.(client).get"
	s, err := c.cl.Logical().Read(path)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.VaultCredentialRequest), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return s, nil
}

func (c *client) post(ctx context.Context, path string, data []byte) (*vault.Secret, error) {
	const op = "vault.(client).post"

	if len(data) == 0 {
		// For POST and PUT methods, Vault requires a valid JSON object be
		// sent even if the JSON object is empty
		data = []byte(`{}`)
	}
	s, err := c.cl.Logical().WriteBytes(path, data)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithCode(errors.VaultCredentialRequest), errors.WithMsg(fmt.Sprintf("vault: %s", c.cl.Address())))
	}
	return s, nil
}

// capabilities calls the /sys/capabilities-self Vault endpoint and returns
// the vault.Secret response. This endpoint is accessible with the default
// policy in Vault 1.7.2. See
// https://www.vaultproject.io/api-docs/system/capabilities-self.
func (c *client) capabilities(ctx context.Context, paths []string) (pathCapabilities, error) {
	const op = "vault.(client).capabilities"
	if len(paths) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "empty paths")
	}
	body := map[string]any{
		"paths": strings.Join(paths, ","),
	}
	reqPath := "sys/capabilities-self"

	secret, err := c.cl.Logical().WriteWithContext(ctx, reqPath, body)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, errors.New(ctx, errors.Unknown, op, "data from Vault is empty")
	}

	var res map[string][]string
	if err := mapstructure.Decode(secret.Data, &res); err != nil {
		return nil, err
	}

	return newPathCapabilities(res), nil
}

// headers returns the underlying Vault Client http headers
func (c *client) headers(_ context.Context) (http.Header, error) {
	return c.cl.Headers(), nil
}

// unwrap accepts a vault token and unwraps it, returning the underlying vault secret
func (c *client) unwrap(ctx context.Context, token string) (*vault.Secret, error) {
	return c.cl.Logical().UnwrapWithContext(ctx, token)
}
