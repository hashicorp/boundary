package vault

import (
	"context"
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
)

func (r *Repository) listRevokePrivateStores(ctx context.Context, opt ...Option) ([]*privateStore, error) {
	const op = "vault.(Repository).listRevokePrivateStores"

	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		limit = opts.withLimit
	}

	var stores []*privateStore
	where, values := "token_status = ?", []interface{}{"revoke"}
	if err := r.reader.SearchWhere(ctx, &stores, where, values, db.WithLimit(limit)); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	for _, store := range stores {
		databaseWrapper, err := r.kms.GetWrapper(ctx, store.ProjectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}
		if err := store.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}
	return stores, nil
}

func (r *Repository) lookupPrivateStore(ctx context.Context, publicId string) (*privateStore, error) {
	const op = "vault.(Repository).lookupPrivateStore"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	ps := allocPrivateStore()
	if err := r.reader.LookupWhere(ctx, &ps, "public_id = ? and token_status = ?", []interface{}{publicId, CurrentToken}); err != nil {
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

type privateStore struct {
	PublicId             string `gorm:"primary_key"`
	ProjectId            string
	Name                 string
	Description          string
	CreateTime           *timestamp.Timestamp
	UpdateTime           *timestamp.Timestamp
	DeleteTime           *timestamp.Timestamp
	Version              uint32
	VaultAddress         string
	Namespace            string
	CaCert               []byte
	TlsServerName        string
	TlsSkipVerify        bool
	WorkerFilter         string
	StoreId              string
	TokenHmac            []byte
	Token                TokenSecret
	CtToken              []byte
	TokenCreateTime      *timestamp.Timestamp
	TokenUpdateTime      *timestamp.Timestamp
	TokenLastRenewalTime *timestamp.Timestamp
	TokenExpirationTime  *timestamp.Timestamp
	TokenRenewalTime     *timestamp.Timestamp
	TokenKeyId           string
	TokenStatus          string
	ClientCert           []byte
	ClientKeyId          string
	ClientKey            KeySecret
	CtClientKey          []byte
	ClientCertKeyHmac    []byte
}

func allocPrivateStore() *privateStore {
	return &privateStore{}
}

func (ps *privateStore) toCredentialStore() *CredentialStore {
	cs := allocCredentialStore()
	cs.PublicId = ps.PublicId
	cs.ProjectId = ps.ProjectId
	cs.Name = ps.Name
	cs.Description = ps.Description
	cs.CreateTime = ps.CreateTime
	cs.UpdateTime = ps.UpdateTime
	cs.DeleteTime = ps.DeleteTime
	cs.Version = ps.Version
	cs.VaultAddress = ps.VaultAddress
	cs.Namespace = ps.Namespace
	cs.CaCert = ps.CaCert
	cs.TlsServerName = ps.TlsServerName
	cs.TlsSkipVerify = ps.TlsSkipVerify
	cs.WorkerFilter = ps.WorkerFilter
	cs.privateToken = ps.token()
	if ps.ClientCert != nil {
		cert := allocClientCertificate()
		cert.StoreId = ps.StoreId
		cert.Certificate = ps.ClientCert
		cert.CtCertificateKey = ps.CtClientKey
		cert.CertificateKeyHmac = ps.ClientCertKeyHmac
		cert.KeyId = ps.ClientKeyId
		cs.privateClientCert = cert
	}
	return cs
}

func (ps *privateStore) token() *Token {
	if ps.TokenHmac != nil {
		tk := allocToken()
		tk.StoreId = ps.StoreId
		tk.TokenHmac = ps.TokenHmac
		tk.LastRenewalTime = ps.TokenLastRenewalTime
		tk.ExpirationTime = ps.TokenExpirationTime
		tk.CreateTime = ps.TokenCreateTime
		tk.UpdateTime = ps.TokenUpdateTime
		tk.CtToken = ps.CtToken
		tk.KeyId = ps.TokenKeyId
		tk.Status = ps.TokenStatus

		return tk
	}

	return nil
}

func (ps *privateStore) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(privateStore).decrypt"

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

func (ps *privateStore) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(privateStore).client"
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
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

// GetPublicId returns the public id.
func (ps *privateStore) GetPublicId() string { return ps.PublicId }

// TableName returns the table name for gorm.
func (ps *privateStore) TableName() string {
	return "credential_vault_store_private"
}
