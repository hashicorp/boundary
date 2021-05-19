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
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	vault "github.com/hashicorp/vault/api"
)

// CreateCredentialStore inserts cs into the repository and returns a new
// CredentialStore containing the credential store's PublicId. cs is not
// changed. cs must not contain a PublicId. The PublicId is generated and
// assigned by this method. cs must contain a valid ScopeId, VaultAddress,
// and Vault token. The Vault token must be renewable, periodic, and
// orphan. CreateCredentialStore calls the /auth/token/renew-self and
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

	accessor, err := renewedToken.TokenAccessor()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get vault token accessor"))
	}

	token, err := newToken(id, cs.inputToken, []byte(accessor), tokenExpires)
	if err != nil {
		return nil, err
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
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

			newCredentialStore.inputToken = nil
			newToken.Token.Token = nil
			newToken.Token.CtToken = nil
			newCredentialStore.outputToken = newToken

			// insert client certificate (if exists)
			if cs.clientCert != nil {
				newClientCertificate = cs.clientCert.clone()
				var clientCertOplogMsg oplog.Message
				if err := w.Create(ctx, newClientCertificate, db.NewOplogMsg(&clientCertOplogMsg)); err != nil {
					return errors.Wrap(err, op)
				}
				msgs = append(msgs, &clientCertOplogMsg)

				newClientCertificate.CertificateKey = nil
				newClientCertificate.CtCertificateKey = nil
				newCredentialStore.clientCert = newClientCertificate

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
		return errors.E(errors.WithCode(errors.VaultTokenNotOrphan), errors.WithOp(op))
	}
	orphan, err := parseutil.ParseBool(s.Data["orphan"])
	if err != nil {
		return errors.Wrap(err, op)
	}
	if !orphan {
		return errors.E(errors.WithCode(errors.VaultTokenNotOrphan), errors.WithOp(op))
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
	TokenHmac            []byte
	TokenCreateTime      *timestamp.Timestamp
	TokenUpdateTime      *timestamp.Timestamp
	TokenLastRenewalTime *timestamp.Timestamp
	TokenExpirationTime  *timestamp.Timestamp
	ClientCert           []byte
	ClientCertKeyHmac    []byte
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

	if agg.TokenHmac != nil {
		tk := allocToken()
		tk.TokenHmac = agg.TokenHmac
		tk.LastRenewalTime = agg.TokenLastRenewalTime
		tk.ExpirationTime = agg.TokenExpirationTime
		tk.CreateTime = agg.TokenCreateTime
		tk.UpdateTime = agg.TokenUpdateTime
		cs.outputToken = tk
	}

	if agg.ClientCert != nil {
		cert := allocClientCertificate()
		cert.Certificate = agg.ClientCert
		cert.CertificateKeyHmac = agg.ClientCertKeyHmac
		cs.clientCert = cert
	}
	return cs
}

// TableName returns the table name for gorm.
func (agg *credentialStoreAggPublic) TableName() string { return "credential_vault_store_agg_public" }

// GetPublicId returns the public id.
func (agg *credentialStoreAggPublic) GetPublicId() string { return agg.PublicId }

func (r *Repository) lookupPrivateCredentialStore(ctx context.Context, publicId string) (*privateCredentialStore, error) {
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
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	if err := pcs.decrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(err, op)
	}

	return pcs, nil
}

type privateCredentialStore struct {
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
	StoreId              string
	TokenHmac            []byte
	Token                []byte
	CtToken              []byte
	TokenCreateTime      *timestamp.Timestamp
	TokenUpdateTime      *timestamp.Timestamp
	TokenLastRenewalTime *timestamp.Timestamp
	TokenExpirationTime  *timestamp.Timestamp
	TokenKeyId           string
	TokenStatus          string
	ClientCert           []byte
	ClientKeyId          string
	ClientKey            []byte
	CtClientKey          []byte
	ClientKeyHmac        []byte
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
	if pcs.TokenHmac != nil {
		tk := allocToken()
		tk.StoreId = pcs.StoreId
		tk.TokenHmac = pcs.TokenHmac
		tk.LastRenewalTime = pcs.TokenLastRenewalTime
		tk.ExpirationTime = pcs.TokenExpirationTime
		tk.CreateTime = pcs.TokenCreateTime
		tk.UpdateTime = pcs.TokenUpdateTime
		tk.CtToken = pcs.CtToken
		tk.KeyId = pcs.TokenKeyId
		tk.Status = pcs.TokenStatus
		cs.privateToken = tk
	}
	if pcs.ClientCert != nil {
		cert := allocClientCertificate()
		cert.StoreId = pcs.StoreId
		cert.Certificate = pcs.ClientCert
		cert.CtCertificateKey = pcs.CtClientKey
		cert.CertificateKeyHmac = pcs.ClientKeyHmac
		cert.KeyId = pcs.ClientKeyId
		cs.privateClientCert = cert
	}
	return cs
}

func (pcs *privateCredentialStore) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(privateCredentialStore).decrypt"

	if pcs.CtToken != nil {
		type ptk struct {
			Token   []byte `wrapping:"pt,token_data"`
			CtToken []byte `wrapping:"ct,token_data"`
		}
		ptkv := &ptk{
			CtToken: pcs.CtToken,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, ptkv, nil); err != nil {
			return errors.Wrap(err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("token"))
		}
		pcs.Token = ptkv.Token
	}

	if pcs.CtClientKey != nil && pcs.ClientCert != nil {
		type pck struct {
			Key   []byte `wrapping:"pt,key_data"`
			CtKey []byte `wrapping:"ct,key_data"`
		}
		pckv := &pck{
			CtKey: pcs.CtClientKey,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, pckv, nil); err != nil {
			return errors.Wrap(err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("client certificate"))
		}
		pcs.ClientKey = pckv.Key
	}
	return nil
}

func (pcs *privateCredentialStore) client() (*client, error) {
	const op = "vault.(privateCredentialStore).client"
	clientConfig := &clientConfig{
		Addr:          pcs.VaultAddress,
		Token:         string(pcs.Token),
		CaCert:        pcs.CaCert,
		TlsServerName: pcs.TlsServerName,
		TlsSkipVerify: pcs.TlsSkipVerify,
		Namespace:     pcs.Namespace,
	}

	if pcs.ClientKey != nil {
		clientConfig.ClientCert = pcs.ClientCert
		clientConfig.ClientKey = pcs.ClientKey
	}

	client, err := newClient(clientConfig)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

// GetPublicId returns the public id.
func (pcs *privateCredentialStore) GetPublicId() string { return pcs.PublicId }

// TableName returns the table name for gorm.
func (pcs *privateCredentialStore) TableName() string {
	return "credential_vault_store_client_private"
}

// UpdateCredentialStore updates the repository entry for cs.PublicId with
// the values in cs for the fields listed in fieldMaskPaths. It returns a
// new CredentialStore containing the updated values and a count of the
// number of records updated. cs is not changed.
//
// cs must contain a valid PublicId. Only Name, Description, Namespace,
// TlsServerName, TlsSkipVerify, CaCert, VaultAddress, Token, and
// ClientCertificate can be changed. If cs.Name is set to a non-empty
// string, it must be unique within cs.ScopeId. If Token is changed, the
// new token must have the same properties defined in CreateCredentialStore
// and UpdateCredentialStore calls the same Vault endpoints described in
// CreateCredentialStore.
//
// An attribute of cs will be set to NULL in the database if the attribute
// in cs is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateCredentialStore(ctx context.Context, cs *CredentialStore, version uint32, fieldMaskPaths []string, _ ...Option) (*CredentialStore, int, error) {
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
	cs = cs.clone()

	var updateToken, updateClientCert, deleteClientCert bool
	var clientCertPlaceholder []byte
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold("Name", f):
		case strings.EqualFold("Description", f):
		case strings.EqualFold("Namespace", f):
		case strings.EqualFold("TlsServerName", f):
		case strings.EqualFold("TlsSkipVerify", f):
		case strings.EqualFold("CaCert", f):
		case strings.EqualFold("VaultAddress", f):
		case strings.EqualFold("Token", f):
			if len(cs.inputToken) != 0 {
				updateToken = true
			}
		case strings.EqualFold("ClientCertificate", f):
			if cs.clientCert != nil &&
				len(cs.clientCert.Certificate) != 0 &&
				len(cs.clientCert.CertificateKey) != 0 {
				clientCertPlaceholder = cs.clientCert.Certificate
				updateClientCert = true
			} else {
				deleteClientCert = true
			}
		default:
			return nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, f)
		}
	}
	var dbMask, nullFields []string
	dbMask, nullFields = dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			"Name":              cs.Name,
			"Description":       cs.Description,
			"Namespace":         cs.Namespace,
			"TlsServerName":     cs.TlsServerName,
			"TlsSkipVerify":     cs.TlsSkipVerify,
			"CaCert":            cs.CaCert,
			"VaultAddress":      cs.VaultAddress,
			"Token":             cs.inputToken,
			"ClientCertificate": clientCertPlaceholder,
		},
		fieldMaskPaths,
		[]string{
			"TlsSkipVerify",
		},
	)
	if len(dbMask) == 0 && len(nullFields) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "missing field mask")
	}
	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch {
		case strings.EqualFold("Token", f):
		case strings.EqualFold("ClientCertificate", f):
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch {
		case strings.EqualFold("Token", f):
		case strings.EqualFold("ClientCertificate", f):
		default:
			filteredNullFields = append(filteredNullFields, f)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	var token *Token
	if updateToken {
		pcs, err := r.lookupPrivateCredentialStore(ctx, cs.GetPublicId())
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to credential store"))
		}

		client, err := pcs.client()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op)
		}
		client.SwapToken(string(cs.inputToken))

		tokenLookup, err := client.LookupToken()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to lookup vault token"))
		}
		if err := validateTokenLookup(op, tokenLookup); err != nil {
			return nil, db.NoRowsAffected, err
		}

		renewedToken, err := client.RenewToken()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to renew vault token"))
		}

		tokenExpires, err := renewedToken.TokenTTL()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get vault token expiration"))
		}

		accessor, err := renewedToken.TokenAccessor()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get vault token accessor"))
		}

		token, err = newToken(cs.GetPublicId(), cs.inputToken, []byte(accessor), tokenExpires)
		if err != nil {
			return nil, db.NoRowsAffected, err
		}

		// encrypt token
		if err := token.encrypt(ctx, databaseWrapper); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op)
		}
	}

	var clientCert *ClientCertificate
	switch {
	case updateClientCert:
		cs.clientCert.StoreId = cs.GetPublicId()
		if err := cs.clientCert.encrypt(ctx, databaseWrapper); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(err, op)
		}
		clientCert = cs.clientCert
	case deleteClientCert:
		clientCert = allocClientCertificate()
		clientCert.StoreId = cs.GetPublicId()
	}

	var rowsUpdated int
	var returnedToken *Token
	var returnedClientCert *ClientCertificate
	var returnedCredentialStore *CredentialStore
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(cs)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
			}

			returnedCredentialStore = cs.clone()
			var csOplogMsg oplog.Message

			switch {
			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
				// the credential store's fields are not being updated,
				// just it's token or client certificate, so we need to
				// just update the credential store's version.
				returnedCredentialStore.Version = version + 1
				rowsUpdated, err = w.Update(ctx, returnedCredentialStore, []string{"Version"}, nil, db.NewOplogMsg(&csOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to update credential store version"))
				}
				if rowsUpdated != 1 {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated credential store version and %d rows updated", rowsUpdated))
				}
			default:
				rowsUpdated, err = w.Update(ctx, returnedCredentialStore, filteredDbMask, filteredNullFields, db.NewOplogMsg(&csOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to update credential store"))
				}
				if rowsUpdated != 1 {
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated credential store and %d rows updated", rowsUpdated))
				}
			}
			msgs = append(msgs, &csOplogMsg)

			if updateToken {
				returnedToken = token.clone()
				query, values := returnedToken.insertQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					return errors.Wrap(err, op)
				}
				if rows > 1 {
					return errors.New(errors.MultipleRecords, op, "more than 1 token would have been created")
				}
				msgs = append(msgs, returnedToken.oplogMessage(db.CreateOp))

				returnedCredentialStore.inputToken = nil
				returnedToken.Token.Token = nil
				returnedToken.Token.CtToken = nil
				returnedCredentialStore.outputToken = returnedToken
			}

			switch {
			case deleteClientCert:
				returnedClientCert = clientCert.clone()
				query, values := returnedClientCert.deleteQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to delete client certificate"))
				}
				if rows > 1 {
					return errors.New(errors.MultipleRecords, op, "more than 1 client certificate would have been deleted")
				}
				msgs = append(msgs, returnedClientCert.oplogMessage(db.DeleteOp))
			case updateClientCert:
				returnedClientCert = clientCert.clone()
				query, values := returnedClientCert.insertQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to update client certificate"))
				}
				if rows > 1 {
					return errors.New(errors.MultipleRecords, op, "more than 1 client certificate would have been upserted")
				}
				returnedClientCert.CertificateKey = nil
				returnedClientCert.CtCertificateKey = nil
				returnedCredentialStore.clientCert = returnedClientCert
				msgs = append(msgs, returnedClientCert.oplogMessage(db.CreateOp))
			}

			publicId := cs.PublicId
			agg := allocCredentialStoreAggPublic()
			agg.PublicId = publicId
			if err := reader.LookupByPublicId(ctx, agg); err != nil {
				return errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("unable to lookup credential store: %s", publicId)))
			}
			returnedCredentialStore = agg.toCredentialStore()

			metadata := cs.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to write oplog"))
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

// ListCredentialStores returns a slice of CredentialStores for the
// scopeIds. WithLimit is the only option supported.
func (r *Repository) ListCredentialStores(ctx context.Context, scopeIds []string, opt ...Option) ([]*CredentialStore, error) {
	const op = "vault.(Repository).ListCredentialStores"
	if len(scopeIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no scopeIds")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var credentialStores []*credentialStoreAggPublic
	err := r.reader.SearchWhere(ctx, &credentialStores, "scope_id in (?)", []interface{}{scopeIds}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	var out []*CredentialStore
	for _, ca := range credentialStores {
		out = append(out, ca.toCredentialStore())
	}
	return out, nil
}

// DeleteCredentialStore deletes publicId from the repository and returns
// the number of records deleted. All options are ignored.
func (r *Repository) DeleteCredentialStore(ctx context.Context, publicId string, _ ...Option) (int, error) {
	const op = "vault.(Repository).DeleteCredentialStore"
	if publicId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "no public id")
	}

	cs := allocCredentialStore()
	cs.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, cs); err != nil {
		if errors.IsNotFoundError(err) {
			return db.NoRowsAffected, nil
		}
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	if cs.ScopeId == "" {
		return db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "no scope id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rowsDeleted int
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			dcs := cs.clone()
			rowsDeleted, err = w.Delete(ctx, dcs, db.WithOplog(oplogWrapper, cs.oplog(oplog.OpType_OP_TYPE_DELETE)))
			if err == nil && rowsDeleted > 1 {
				return errors.New(errors.MultipleRecords, op, "more than 1 CredentialStore would have been deleted")
			}
			return err
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", cs.PublicId)))
	}

	return rowsDeleted, nil
}
