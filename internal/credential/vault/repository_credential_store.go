package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/db"
	dbcommon "github.com/hashicorp/boundary/internal/db/common"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/sdk/parseutil"
	vault "github.com/hashicorp/vault/api"
)

// CreateCredentialStore inserts cs into the repository and returns a new
// CredentialStore containing the credential store's PublicId. cs is not
// changed. cs must not contain a PublicId. The PublicId is generated and
// assigned by this method. cs must contain a valid ScopeId, VaultAddress,
// and Vault token. The Vault token must be renewable, periodic, and
// orphaned. CreateCredentialStore calls the /auth/token/renew-self and
// /auth/token/lookup-self Vault endpoints.
//
// Both cs.Name and cs.Description are optional. If cs.Name is set, it must
// be unique within cs.ScopeId. Both cs.CreateTime and cs.UpdateTime are
// ignored.
//
// For more information about the required properties of the Vault token see:
// https://www.vaultproject.io/api-docs/auth/token#period,
// https://www.vaultproject.io/api-docs/auth/token#renewable,
// https://www.vaultproject.io/docs/concepts/tokens#token-hierarchies-and-orphan-tokens,
// https://www.vaultproject.io/docs/concepts/tokens#periodic-tokens, and
// https://www.vaultproject.io/docs/concepts/tokens#token-time-to-live-periodic-tokens-and-explicit-max-ttls.
//
// For more information about the Vault endpoints called by
// CreateCredentialStore see:
// https://www.vaultproject.io/api-docs/auth/token#renew-a-token-self and
// https://www.vaultproject.io/api-docs/auth/token#lookup-a-token-self.
func (r *Repository) CreateCredentialStore(ctx context.Context, cs *CredentialStore, _ ...Option) (*CredentialStore, error) {
	const op = "vault.(Repository).CreateCredentialStore"
	if cs == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil CredentialStore")
	}
	if cs.CredentialStore == nil {
		return nil, errors.New(errors.InvalidParameter, op, "nil embedded CredentialStore")
	}
	if cs.ScopeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no scope id")
	}
	if len(cs.inputToken) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no vault token")
	}
	if cs.VaultAddress == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no vault address")
	}
	if cs.PublicId != "" {
		return nil, errors.New(errors.InvalidParameter, op, "public id not empty")
	}

	cs = cs.clone()

	id, err := newCredentialStoreId()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	cs.PublicId = id

	clientConfig := &clientConfig{
		Addr:          cs.VaultAddress,
		Token:         string(cs.inputToken),
		CaCert:        cs.CaCert,
		TlsServerName: cs.TlsServerName,
		TlsSkipVerify: cs.TlsSkipVerify,
		Namespace:     cs.Namespace,
	}

	if cs.clientCert != nil {
		cs.clientCert.StoreId = id
		clientConfig.ClientCert = cs.clientCert.GetCertificate()
		clientConfig.ClientKey = cs.clientCert.GetCertificateKey()
	}

	client, err := newClient(clientConfig)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to create vault client"))
	}

	tokenLookup, err := client.LookupToken()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to lookup vault token"))
	}
	if err := validateTokenLookup(op, tokenLookup); err != nil {
		return nil, err
	}
	renewedToken, err := client.RenewToken()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to renew vault token"))
	}

	tokenExpires, err := renewedToken.TokenTTL()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get vault token expiration"))
	}

	token, err := newToken(id, cs.inputToken, tokenExpires)
	if err != nil {
		return nil, err
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"), errors.WithCode(errors.Encrypt))
	}

	// encrypt
	if err := token.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(err, op)
	}
	if cs.clientCert != nil {
		if err := cs.clientCert.encrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(err, op)
		}
	}

	var newToken *Token
	var newClientCertificate *ClientCertificate
	var newCredentialStore *CredentialStore
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(cs)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}

			// insert credential store
			newCredentialStore = cs.clone()
			var csOplogMsg oplog.Message
			if err := w.Create(ctx, newCredentialStore, db.NewOplogMsg(&csOplogMsg)); err != nil {
				return errors.Wrap(err, op)
			}
			msgs = append(msgs, &csOplogMsg)

			// insert token
			newToken = token.clone()
			query, values := newToken.insertQuery()
			rows, err := w.Exec(ctx, query, values)
			if err != nil {
				return errors.Wrap(err, op)
			}
			if rows > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 token would have been created")
			}
			msgs = append(msgs, newToken.oplogMessage(db.CreateOp))

			// insert client certificate (if exists)
			if cs.clientCert != nil {
				newClientCertificate = cs.clientCert.clone()
				var clientCertOplogMsg oplog.Message
				if err := w.Create(ctx, newClientCertificate, db.NewOplogMsg(&clientCertOplogMsg)); err != nil {
					return errors.Wrap(err, op)
				}
				msgs = append(msgs, &clientCertOplogMsg)
			}
			metadata := cs.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("in scope: %s: name %s already exists", cs.ScopeId, cs.Name)))
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("in scope: %s", cs.ScopeId)))
	}
	return newCredentialStore, nil
}

func validateTokenLookup(op errors.Op, s *vault.Secret) error {
	if s.Data == nil {
		return errors.New(errors.InvalidParameter, op, "vault secret is not a token lookup")
	}

	if s.Data["renewable"] == nil {
		return errors.E(errors.WithCode(errors.VaultTokenNotRenewable), errors.WithOp(op))
	}
	renewable, err := parseutil.ParseBool(s.Data["renewable"])
	if err != nil {
		return errors.Wrap(err, op)
	}
	if !renewable {
		return errors.E(errors.WithCode(errors.VaultTokenNotRenewable), errors.WithOp(op))
	}

	if s.Data["orphan"] == nil {
		return errors.E(errors.WithCode(errors.VaultTokenNotOrphaned), errors.WithOp(op))
	}
	orphaned, err := parseutil.ParseBool(s.Data["orphan"])
	if err != nil {
		return errors.Wrap(err, op)
	}
	if !orphaned {
		return errors.E(errors.WithCode(errors.VaultTokenNotOrphaned), errors.WithOp(op))
	}

	if s.Data["period"] == nil {
		return errors.E(errors.WithCode(errors.VaultTokenNotPeriodic), errors.WithOp(op))
	}

	return nil
}

// LookupCredentialStore returns the CredentialStore for publicId. Returns
// nil, nil if no CredentialStore is found for publicId.
func (r *Repository) LookupCredentialStore(ctx context.Context, publicId string, _ ...Option) (*CredentialStore, error) {
	const op = "vault.(Repository).LookupCredentialStore"
	if publicId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no public id")
	}
	agg := allocCredentialStoreAggPublic()
	agg.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, agg); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}
	return agg.toCredentialStore(), nil
}

type credentialStoreAggPublic struct {
	PublicId             string `gorm:"primary_key"`
	ScopeId              string
	Name                 string
	Description          string
	CreateTime           *timestamp.Timestamp
	UpdateTime           *timestamp.Timestamp
	Version              uint32
	VaultAddress         string
	Namespace            string
	CaCert               []byte
	TlsServerName        string
	TlsSkipVerify        bool
	TokenSha256          []byte
	TokenCreateTime      *timestamp.Timestamp
	TokenUpdateTime      *timestamp.Timestamp
	TokenLastRenewalTime *timestamp.Timestamp
	TokenExpirationTime  *timestamp.Timestamp
	ClientCertificate    []byte
}

func allocCredentialStoreAggPublic() *credentialStoreAggPublic {
	return &credentialStoreAggPublic{}
}

func (agg *credentialStoreAggPublic) toCredentialStore() *CredentialStore {
	cs := allocCredentialStore()
	cs.PublicId = agg.PublicId
	cs.ScopeId = agg.ScopeId
	cs.Name = agg.Name
	cs.Description = agg.Description
	cs.CreateTime = agg.CreateTime
	cs.UpdateTime = agg.UpdateTime
	cs.Version = agg.Version
	cs.VaultAddress = agg.VaultAddress
	cs.Namespace = agg.Namespace
	cs.CaCert = agg.CaCert
	cs.TlsServerName = agg.TlsServerName
	cs.TlsSkipVerify = agg.TlsSkipVerify

	if agg.TokenSha256 != nil {
		tk := allocToken()
		tk.TokenSha256 = agg.TokenSha256
		tk.LastRenewalTime = agg.TokenLastRenewalTime
		tk.ExpirationTime = agg.TokenExpirationTime
		tk.CreateTime = agg.TokenCreateTime
		tk.UpdateTime = agg.TokenUpdateTime
		cs.outputToken = tk
	}

	if agg.ClientCertificate != nil {
		cert := allocClientCertificate()
		cert.Certificate = agg.ClientCertificate
		cs.clientCert = cert
	}
	return cs
}

// TableName returns the table name for gorm.
func (agg *credentialStoreAggPublic) TableName() string { return "credential_vault_store_agg_public" }

// GetPublicId returns the public id.
func (agg *credentialStoreAggPublic) GetPublicId() string { return agg.PublicId }

// UpdateCredentialStore updates the repository entry for cs.PublicId with
// the values in cs for the fields listed in fieldMaskPaths. It returns a
// new CredentialStore containing the updated values and a count of the
// number of records updated. cs is not changed.
//
// cs must contain a valid PublicId. Only cs.Name and cs.Description can be
// updated. If cs.Name is set to a non-empty string, it must be unique
// within cs.ScopeId.
//
// An attribute of cs will be set to NULL in the database if the attribute
// in cs is the zero value and it is included in fieldMaskPaths.
//
// TODO(mgaffney) 04/2021: Add interactions with Vault to godoc
func (r *Repository) UpdateCredentialStore(ctx context.Context, cs *CredentialStore, version uint32, fieldMaskPaths []string, opt ...Option) (*CredentialStore, int, error) {
	const op = "vault.(Repository).UpdateCredentialStore"
	if cs == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing CredentialStore")
	}
	if cs.CredentialStore == nil {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing embedded CredentialStore")
	}
	if cs.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing version")
	}
	if cs.ScopeId == "" {
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "missing scope id")
	}

	// TODO(mgaffney) 04/2021: If token or vault address,
	// connect to vault server and test token.

	// TODO(mgaffney) 04/2021:
	// If token is updated
	// 	if current token has leases
	// 	  set current token status to 'maintaining'
	// 	else
	// 	  revoke current token and set status to 'revoked'

	// TODO(mgaffney) 04/2021: Fields to handle:
	// - ca cert
	// - client cert
	// - vault address
	// - vault token
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("Namespace", f):
		case strings.EqualFold("TlsServerName", f):
		case strings.EqualFold("TlsSkipVerify", f):
		case strings.EqualFold("CaCert", f):
		case strings.EqualFold("Token", f):
		default:
			return nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":          cs.Name,
			"Description":   cs.Description,
			"Namespace":     cs.Namespace,
			"TlsServerName": cs.TlsServerName,
			"TlsSkipVerify": cs.TlsSkipVerify,
			"CaCert":        cs.CaCert,
		},
		fieldMaskPaths,
		[]string{
			"TlsSkipVerify",
		},
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "missing field mask")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithCode(errors.Encrypt),
			errors.WithMsg(("unable to get oplog wrapper")))
	}

	var rowsUpdated int
	var returnedCredentialStore *CredentialStore
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			returnedCredentialStore = cs.clone()
			var err error
			rowsUpdated, err = w.Update(ctx, returnedCredentialStore, dbMask, nullFields,
				db.WithOplog(oplogWrapper, cs.oplog(oplog.OpType_OP_TYPE_UPDATE)),
				db.WithVersion(&version))
			if err == nil && rowsUpdated > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 resource would have been updated")
			}
			return err
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(errors.NotUnique, op,
				fmt.Sprintf("name %s already exists: %s", cs.Name, cs.PublicId))
		}
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(cs.PublicId))
	}

	return returnedCredentialStore, rowsUpdated, nil
}

func (r *Repository) lookupPrivateCredentialStore(ctx context.Context, publicId string) (*CredentialStore, error) {
	const op = "vault.(Repository).lookupPrivateCredentialStore"
	if publicId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no public id")
	}
	pcs := allocPrivateCredentialStore()
	pcs.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, pcs); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, pcs.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"), errors.WithCode(errors.Encrypt))
	}

	cs := pcs.toCredentialStore()
	if cs.privateToken != nil {
		if err := cs.privateToken.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(err, op)
		}
	}
	if cs.privateClientCert != nil {
		if err := cs.privateClientCert.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(err, op)
		}
	}
	return cs, nil
}

type privateCredentialStore struct {
	PublicId               string `gorm:"primary_key"`
	ScopeId                string
	Name                   string
	Description            string
	CreateTime             *timestamp.Timestamp
	UpdateTime             *timestamp.Timestamp
	Version                uint32
	VaultAddress           string
	Namespace              string
	CaCert                 []byte
	TlsServerName          string
	TlsSkipVerify          bool
	StoreId                string
	TokenSha256            []byte
	CtToken                []byte
	TokenCreateTime        *timestamp.Timestamp
	TokenUpdateTime        *timestamp.Timestamp
	TokenLastRenewalTime   *timestamp.Timestamp
	TokenExpirationTime    *timestamp.Timestamp
	TokenKeyId             string
	TokenStatus            string
	ClientCertificate      []byte
	CtClientCertificateKey []byte
	ClientCertificateKeyId string
}

func allocPrivateCredentialStore() *privateCredentialStore {
	return &privateCredentialStore{}
}

func (pcs *privateCredentialStore) toCredentialStore() *CredentialStore {
	cs := allocCredentialStore()
	cs.PublicId = pcs.PublicId
	cs.ScopeId = pcs.ScopeId
	cs.Name = pcs.Name
	cs.Description = pcs.Description
	cs.CreateTime = pcs.CreateTime
	cs.UpdateTime = pcs.UpdateTime
	cs.Version = pcs.Version
	cs.VaultAddress = pcs.VaultAddress
	cs.Namespace = pcs.Namespace
	cs.CaCert = pcs.CaCert
	cs.TlsServerName = pcs.TlsServerName
	cs.TlsSkipVerify = pcs.TlsSkipVerify
	if pcs.TokenSha256 != nil {
		tk := allocToken()
		tk.StoreId = pcs.StoreId
		tk.TokenSha256 = pcs.TokenSha256
		tk.LastRenewalTime = pcs.TokenLastRenewalTime
		tk.ExpirationTime = pcs.TokenExpirationTime
		tk.CreateTime = pcs.TokenCreateTime
		tk.UpdateTime = pcs.TokenUpdateTime
		tk.CtToken = pcs.CtToken
		tk.KeyId = pcs.TokenKeyId
		tk.Status = pcs.TokenStatus
		cs.privateToken = tk
	}
	if pcs.ClientCertificate != nil {
		cert := allocClientCertificate()
		cert.StoreId = pcs.StoreId
		cert.Certificate = pcs.ClientCertificate
		cert.CtCertificateKey = pcs.CtClientCertificateKey
		cert.KeyId = pcs.ClientCertificateKeyId
		cs.privateClientCert = cert
	}
	return cs
}

// GetPublicId returns the public id.
func (pcs *privateCredentialStore) GetPublicId() string { return pcs.PublicId }

// TableName returns the table name for gorm.
func (pcs *privateCredentialStore) TableName() string {
	return "credential_vault_store_client_private"
}
