// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
)

func (r *Repository) lookupClientStore(ctx context.Context, publicId string) (*clientStore, error) {
	const op = "vault.(Repository).lookupClientStore"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	ps := allocClientStore()
	if err := r.reader.LookupWhere(ctx, &ps, "public_id = ?", []any{publicId}); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, ps.ProjectId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	if err := ps.decrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	return ps, nil
}

// clientStore is a Vault credential store that contains all the data needed to create
// a Vault client. If the Vault token for the store is expired all token data will be null
// other than the status of expired.
type clientStore struct {
	PublicId            string `gorm:"primary_key"`
	ProjectId           string
	DeleteTime          *timestamp.Timestamp
	VaultAddress        string
	Namespace           string
	CaCert              []byte
	TlsServerName       string
	TlsSkipVerify       bool
	WorkerFilter        string
	TokenHmac           []byte
	Token               TokenSecret
	CtToken             []byte
	TokenRenewalTime    *timestamp.Timestamp
	TokenKeyId          string
	TokenStatus         string
	TokenExpirationTime *timestamp.Timestamp
	ClientCert          []byte
	ClientKeyId         string
	ClientKey           KeySecret
	CtClientKey         []byte
}

func allocClientStore() *clientStore {
	return &clientStore{}
}

func (ps *clientStore) toCredentialStore() *CredentialStore {
	cs := allocCredentialStore()
	cs.PublicId = ps.PublicId
	cs.ProjectId = ps.ProjectId
	cs.DeleteTime = ps.DeleteTime
	cs.VaultAddress = ps.VaultAddress
	cs.Namespace = ps.Namespace
	cs.CaCert = ps.CaCert
	cs.TlsServerName = ps.TlsServerName
	cs.TlsSkipVerify = ps.TlsSkipVerify
	cs.WorkerFilter = ps.WorkerFilter
	cs.privateToken = ps.token()
	if ps.ClientCert != nil {
		cert := allocClientCertificate()
		cert.StoreId = ps.PublicId
		cert.Certificate = ps.ClientCert
		cert.CtCertificateKey = ps.CtClientKey
		cert.KeyId = ps.ClientKeyId
		cs.privateClientCert = cert
	}
	return cs
}

func (ps *clientStore) token() *Token {
	if ps.TokenHmac != nil {
		tk := allocToken()
		tk.TokenHmac = ps.TokenHmac
		tk.Status = ps.TokenStatus
		tk.CtToken = ps.CtToken
		tk.KeyId = ps.TokenKeyId
		tk.ExpirationTime = ps.TokenExpirationTime
		return tk
	}

	return nil
}

func (ps *clientStore) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(clientStore).decrypt"

	if ps.CtToken != nil {
		type ptk struct {
			Token   []byte `wrapping:"pt,token_data"`
			CtToken []byte `wrapping:"ct,token_data"`
		}
		ptkv := &ptk{
			CtToken: ps.CtToken,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, ptkv, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("token"))
		}
		ps.Token = ptkv.Token
	}

	if ps.CtClientKey != nil && ps.ClientCert != nil {
		type pck struct {
			Key   []byte `wrapping:"pt,key_data"`
			CtKey []byte `wrapping:"ct,key_data"`
		}
		pckv := &pck{
			CtKey: ps.CtClientKey,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, pckv, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("client certificate"))
		}
		ps.ClientKey = pckv.Key
	}
	return nil
}

func (ps *clientStore) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(clientStore).client"
	clientConfig := &clientConfig{
		Addr:          ps.VaultAddress,
		Token:         ps.Token,
		CaCert:        ps.CaCert,
		TlsServerName: ps.TlsServerName,
		TlsSkipVerify: ps.TlsSkipVerify,
		Namespace:     ps.Namespace,
	}

	if ps.ClientKey != nil {
		clientConfig.ClientCert = ps.ClientCert
		clientConfig.ClientKey = ps.ClientKey
	}

	client, err := vaultClientFactoryFn(ctx, clientConfig, WithWorkerFilter(ps.WorkerFilter))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

// GetPublicId returns the public id.
func (ps *clientStore) GetPublicId() string { return ps.PublicId }

// TableName returns the table name for gorm.
func (ps *clientStore) TableName() string {
	return "credential_vault_store_client"
}

// renewRevokeStore is a clientStore that is not limited to the current token and includes
// 'current', 'maintaining' and 'revoke' tokens.
type renewRevokeStore struct {
	Store *clientStore `gorm:"embedded"`
}

func allocRenewRevokeStore() *renewRevokeStore {
	return &renewRevokeStore{
		Store: allocClientStore(),
	}
}

// TableName returns the table name for gorm.
func (ps *renewRevokeStore) TableName() string {
	return "credential_vault_token_renewal_revocation"
}
