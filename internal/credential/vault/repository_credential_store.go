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
	"github.com/hashicorp/go-secure-stdlib/parseutil"
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
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil CredentialStore")
	}
	if cs.CredentialStore == nil {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "nil embedded CredentialStore")
	}
	if cs.ScopeId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}
	if len(cs.inputToken) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no vault token")
	}
	if cs.VaultAddress == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no vault address")
	}
	if cs.PublicId != "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "public id not empty")
	}
	if cs.clientCert != nil && len(cs.clientCert.CertificateKey) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "client certificate without private key")
	}

	cs = cs.clone()

	id, err := newCredentialStoreId()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cs.PublicId = id
	if cs.clientCert != nil {
		cs.clientCert.StoreId = id
	}

	client, err := cs.client()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create vault client"))
	}
	tokenLookup, err := client.lookupToken()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup vault token"))
	}
	if err := validateTokenLookup(op, tokenLookup); err != nil {
		return nil, err
	}

	available, err := client.capabilities(requiredCapabilities.paths())
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get vault capabilities"))
	}
	missing := available.missing(requiredCapabilities)
	if len(missing) > 0 {
		return nil,
			errors.New(ctx, errors.VaultTokenMissingCapabilities, op, fmt.Sprintf("missing capabilites: %v", missing))
	}

	renewedToken, err := client.renewToken()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to renew vault token"))
	}

	tokenExpires, err := renewedToken.TokenTTL()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get vault token expiration"))
	}

	accessor, err := renewedToken.TokenAccessor()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get vault token accessor"))
	}

	token, err := newToken(id, cs.inputToken, []byte(accessor), tokenExpires)
	if err != nil {
		return nil, err
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	// encrypt
	if err := token.encrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if cs.clientCert != nil {
		if err := cs.clientCert.encrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	var newToken *Token
	var newClientCertificate *ClientCertificate
	var newCredentialStore *CredentialStore
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(ctx, cs)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			// insert credential store
			newCredentialStore = cs.clone()
			var csOplogMsg oplog.Message
			if err := w.Create(ctx, newCredentialStore, db.NewOplogMsg(&csOplogMsg)); err != nil {
				return errors.Wrap(ctx, err, op)
			}
			msgs = append(msgs, &csOplogMsg)

			// insert token
			newToken = token.clone()
			query, values := newToken.insertQuery()
			rows, err := w.Exec(ctx, query, values)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rows > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 token would have been created")
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
					return errors.Wrap(ctx, err, op)
				}
				msgs = append(msgs, &clientCertOplogMsg)

				newClientCertificate.CertificateKey = nil
				newClientCertificate.CtCertificateKey = nil
				newCredentialStore.clientCert = newClientCertificate

			}
			metadata := cs.oplog(oplog.OpType_OP_TYPE_CREATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s: name %s already exists", cs.ScopeId, cs.Name)))
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("in scope: %s", cs.ScopeId)))
	}

	// Best effort update next run time of token renewal job, but an error should not
	// cause update to fail.
	// TODO (lcr 05/2021): log error once repo has logger
	_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, tokenRenewalJobName, token.renewalIn())

	return newCredentialStore, nil
}

func validateTokenLookup(op errors.Op, s *vault.Secret) error {
	if s.Data == nil {
		return errors.NewDeprecated(errors.InvalidParameter, op, "vault secret is not a token lookup")
	}

	if s.Data["renewable"] == nil {
		return errors.EDeprecated(errors.WithCode(errors.VaultTokenNotRenewable), errors.WithOp(op))
	}
	renewable, err := parseutil.ParseBool(s.Data["renewable"])
	if err != nil {
		return errors.WrapDeprecated(err, op)
	}
	if !renewable {
		return errors.EDeprecated(errors.WithCode(errors.VaultTokenNotRenewable), errors.WithOp(op))
	}

	if s.Data["orphan"] == nil {
		return errors.EDeprecated(errors.WithCode(errors.VaultTokenNotOrphan), errors.WithOp(op))
	}
	orphan, err := parseutil.ParseBool(s.Data["orphan"])
	if err != nil {
		return errors.WrapDeprecated(err, op)
	}
	if !orphan {
		return errors.EDeprecated(errors.WithCode(errors.VaultTokenNotOrphan), errors.WithOp(op))
	}

	if s.Data["period"] == nil {
		return errors.EDeprecated(errors.WithCode(errors.VaultTokenNotPeriodic), errors.WithOp(op))
	}

	return nil
}

// LookupCredentialStore returns the CredentialStore for publicId. Returns
// nil, nil if no CredentialStore is found for publicId.
func (r *Repository) LookupCredentialStore(ctx context.Context, publicId string, _ ...Option) (*CredentialStore, error) {
	const op = "vault.(Repository).LookupCredentialStore"
	if publicId == "" {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}
	agg := allocPublicStore()
	agg.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, agg); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}
	return agg.toCredentialStore(), nil
}

type publicStore struct {
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

func allocPublicStore() *publicStore {
	return &publicStore{}
}

func (ps *publicStore) toCredentialStore() *CredentialStore {
	cs := allocCredentialStore()
	cs.PublicId = ps.PublicId
	cs.ScopeId = ps.ScopeId
	cs.Name = ps.Name
	cs.Description = ps.Description
	cs.CreateTime = ps.CreateTime
	cs.UpdateTime = ps.UpdateTime
	cs.Version = ps.Version
	cs.VaultAddress = ps.VaultAddress
	cs.Namespace = ps.Namespace
	cs.CaCert = ps.CaCert
	cs.TlsServerName = ps.TlsServerName
	cs.TlsSkipVerify = ps.TlsSkipVerify

	if ps.TokenHmac != nil {
		tk := allocToken()
		tk.TokenHmac = ps.TokenHmac
		tk.LastRenewalTime = ps.TokenLastRenewalTime
		tk.ExpirationTime = ps.TokenExpirationTime
		tk.CreateTime = ps.TokenCreateTime
		tk.UpdateTime = ps.TokenUpdateTime
		cs.outputToken = tk
	}

	if ps.ClientCert != nil {
		cert := allocClientCertificate()
		cert.Certificate = ps.ClientCert
		cert.CertificateKeyHmac = ps.ClientCertKeyHmac
		cs.clientCert = cert
	}
	return cs
}

// TableName returns the table name for gorm.
func (_ *publicStore) TableName() string { return "credential_vault_store_public" }

// GetPublicId returns the public id.
func (ps *publicStore) GetPublicId() string { return ps.PublicId }

// UpdateCredentialStore updates the repository entry for cs.PublicId with
// the values in cs for the fields listed in fieldMaskPaths. It returns a
// new CredentialStore containing the updated values and a count of the
// number of records updated. cs is not changed.
//
// cs must contain a valid PublicId. Only Name, Description, Namespace,
// TlsServerName, TlsSkipVerify, CaCert, VaultAddress, ClientCertificate,
// ClientCertificateKey, and Token can be changed. If cs.Name is set to a
// non-empty string, it must be unique within cs.ScopeId. If Token is changed,
// the new token must have the same properties defined in CreateCredentialStore
// and UpdateCredentialStore calls the same Vault endpoints described in
// CreateCredentialStore.
//
// An attribute of cs will be set to NULL in the database if the attribute
// in cs is the zero value and it is included in fieldMaskPaths.
func (r *Repository) UpdateCredentialStore(ctx context.Context, cs *CredentialStore, version uint32, fieldMaskPaths []string, _ ...Option) (*CredentialStore, int, error) {
	const op = "vault.(Repository).UpdateCredentialStore"
	if cs == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing CredentialStore")
	}
	if cs.CredentialStore == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing embedded CredentialStore")
	}
	if cs.PublicId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidPublicId, op, "missing public id")
	}
	if version == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing version")
	}
	if cs.ScopeId == "" {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "missing scope id")
	}
	cs = cs.clone()

	var validateToken, updateToken bool
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(nameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(namespaceField, f):
		case strings.EqualFold(tlsServerNameField, f):
		case strings.EqualFold(tlsSkipVerifyField, f):
		case strings.EqualFold(caCertField, f):
		case strings.EqualFold(vaultAddressField, f):
			validateToken = true
		case strings.EqualFold(certificateField, f):
		case strings.EqualFold(certificateKeyField, f):
		case strings.EqualFold(tokenField, f):
			if len(cs.inputToken) != 0 {
				updateToken = true
				validateToken = true
			}
		default:
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidFieldMask, op, f)
		}
	}
	dbMask, nullFields := dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			nameField:          cs.Name,
			descriptionField:   cs.Description,
			namespaceField:     cs.Namespace,
			tlsServerNameField: cs.TlsServerName,
			tlsSkipVerifyField: cs.TlsSkipVerify,
			caCertField:        cs.CaCert,
			vaultAddressField:  cs.VaultAddress,
			tokenField:         cs.inputToken,
		},
		fieldMaskPaths,
		[]string{
			tlsSkipVerifyField,
		},
	)
	var clientCert, clientCertKey []byte
	if cs.ClientCertificate() != nil {
		clientCert = cs.ClientCertificate().GetCertificate()
		clientCertKey = cs.ClientCertificate().GetCertificateKey()
	}
	certDbMask, certNullFields := dbcommon.BuildUpdatePaths(
		map[string]interface{}{
			certificateField:    clientCert,
			certificateKeyField: clientCertKey,
		},
		fieldMaskPaths, nil,
	)
	if len(certNullFields) != 0 && len(certNullFields) != 2 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "attempting to unset a required field on a client cert")
	}
	if len(append(dbMask, certDbMask...)) == 0 && len(append(nullFields, certNullFields...)) == 0 {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.EmptyFieldMask, op, "missing field mask")
	}

	var filteredDbMask, filteredNullFields []string
	for _, f := range dbMask {
		switch {
		case strings.EqualFold(tokenField, f):
		default:
			filteredDbMask = append(filteredDbMask, f)
		}
	}
	for _, f := range nullFields {
		switch {
		case strings.EqualFold(tokenField, f):
			return nil, db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "attempting to unset the value for token")
		default:
			filteredNullFields = append(filteredNullFields, f)
		}
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}
	databaseWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, db.NoRowsAffected,
			errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
	}

	ps, err := r.lookupPrivateStore(ctx, cs.GetPublicId())
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to lookup private credential store"))
	}
	if ps == nil {
		return nil, db.NoRowsAffected, errors.New(ctx, errors.RecordNotFound, op, fmt.Sprintf("credential store %s", cs.PublicId))
	}
	origStore := ps.toCredentialStore()
	origStore.inputToken = ps.Token
	if len(ps.ClientCert) > 0 {
		origStore.clientCert, err = NewClientCertificate(ps.ClientCert, ps.ClientKey)
	}
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("can't recreate client certificate for vault client creation"))
	}
	updatedStore := origStore.applyUpdate(cs, fieldMaskPaths)

	if len(certDbMask) > 0 && updatedStore.clientCert != nil {
		if err := updatedStore.clientCert.encrypt(ctx, databaseWrapper); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}

	var token *Token
	client, err := updatedStore.client()
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get client for updated store"))
	}
	if validateToken {
		tokenLookup, err := client.lookupToken()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("cannot lookup token for updated store"))
		}
		if err := validateTokenLookup(op, tokenLookup); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}

		available, err := client.capabilities(requiredCapabilities.paths())
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get vault capabilities"))
		}
		missing := available.missing(requiredCapabilities)
		if len(missing) > 0 {
			return nil,
				db.NoRowsAffected,
				errors.New(ctx, errors.VaultTokenMissingCapabilities, op, fmt.Sprintf("missing capabilites: %v", missing))
		}
	}
	if updateToken {
		renewedToken, err := client.renewToken()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to renew vault token"))
		}
		tokenExpires, err := renewedToken.TokenTTL()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get vault token expiration"))
		}
		accessor, err := renewedToken.TokenAccessor()
		if err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get vault token accessor"))
		}
		if token, err = newToken(cs.GetPublicId(), cs.inputToken, []byte(accessor), tokenExpires); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
		// encrypt token
		if err := token.encrypt(ctx, databaseWrapper); err != nil {
			return nil, db.NoRowsAffected, errors.Wrap(ctx, err, op)
		}
	}

	var rowsUpdated int
	var returnedCredentialStore *CredentialStore
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(ctx, cs)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			cs := cs.clone()
			var csOplogMsg oplog.Message

			switch {
			case len(filteredDbMask) == 0 && len(filteredNullFields) == 0:
				// the credential store's fields are not being updated,
				// just it's token or client certificate, so we need to
				// just update the credential store's version.
				cs.Version = version + 1
				rowsUpdated, err = w.Update(ctx, cs, []string{"Version"}, nil, db.NewOplogMsg(&csOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential store version"))
				}
				switch rowsUpdated {
				case 1:
				case 0:
					return nil
				default:
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated credential store version and %d rows updated", rowsUpdated))
				}
			default:
				rowsUpdated, err = w.Update(ctx, cs, filteredDbMask, filteredNullFields, db.NewOplogMsg(&csOplogMsg), db.WithVersion(&version))
				if err != nil {
					if errors.IsUniqueError(err) {
						return errors.New(ctx, errors.NotUnique, op,
							fmt.Sprintf("name %s already exists: %s", cs.Name, cs.PublicId))
					}
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to update credential store"))
				}
				switch rowsUpdated {
				case 1:
				case 0:
					return nil
				default:
					return errors.New(ctx, errors.MultipleRecords, op, fmt.Sprintf("updated credential store and %d rows updated", rowsUpdated))
				}
			}
			msgs = append(msgs, &csOplogMsg)

			switch {
			case len(certNullFields) == 2:
				// Delete the certificate
				deleteCert := allocClientCertificate()
				deleteCert.StoreId = cs.GetPublicId()
				query, values := deleteCert.deleteQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to delete client certificate"))
				}
				if rows > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 client certificate would have been deleted")
				}
				msgs = append(msgs, deleteCert.oplogMessage(db.DeleteOp))
			case len(certDbMask) > 0:
				if updatedStore.clientCert == nil {
					return errors.New(ctx, errors.InvalidParameter, op, "updated cert")
				}
				query, values := updatedStore.clientCert.insertQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					return errors.Wrap(ctx, err, op, errors.WithMsg("unable to upsert client certificate"))
				}
				if rows > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 client certificate would have been upserted")
				}
			}

			if updateToken {
				query, values := token.insertQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					if errors.IsUniqueError(err) {
						return errors.New(ctx, errors.NotUnique, op,
							fmt.Sprintf("token already exists"))
					}
					return errors.Wrap(ctx, err, op)
				}
				if rows > 1 {
					return errors.New(ctx, errors.MultipleRecords, op, "more than 1 token would have been created")
				}
				msgs = append(msgs, token.oplogMessage(db.CreateOp))
			}

			publicId := cs.PublicId
			agg := allocPublicStore()
			agg.PublicId = publicId
			if err := reader.LookupByPublicId(ctx, agg); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("unable to lookup credential store: %s", publicId)))
			}
			returnedCredentialStore = agg.toCredentialStore()

			metadata := cs.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}
			return nil
		},
	)

	if err != nil {
		return nil, db.NoRowsAffected, err
	}

	if updateToken && token != nil {
		// Best effort update next run time of token renewal job, but an error should not
		// cause update to fail.
		// TODO (lcr 05/2021): log error once repo has logger
		_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, tokenRenewalJobName, token.renewalIn())
	}

	return returnedCredentialStore, rowsUpdated, nil
}

// ListCredentialStores returns a slice of CredentialStores for the
// scopeIds. WithLimit is the only option supported.
func (r *Repository) ListCredentialStores(ctx context.Context, scopeIds []string, opt ...Option) ([]*CredentialStore, error) {
	const op = "vault.(Repository).ListCredentialStores"
	if len(scopeIds) == 0 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "no scopeIds")
	}
	opts := getOpts(opt...)
	limit := r.defaultLimit
	if opts.withLimit != 0 {
		// non-zero signals an override of the default limit for the repo.
		limit = opts.withLimit
	}
	var credentialStores []*publicStore
	err := r.reader.SearchWhere(ctx, &credentialStores, "scope_id in (?)", []interface{}{scopeIds}, db.WithLimit(limit))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
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
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no public id")
	}

	cs := allocCredentialStore()
	cs.PublicId = publicId
	if err := r.reader.LookupByPublicId(ctx, cs); err != nil {
		if errors.IsNotFoundError(err) {
			return db.NoRowsAffected, nil
		}
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("failed for %s", publicId)))
	}
	if cs.ScopeId == "" {
		return db.NoRowsAffected, errors.New(ctx, errors.InvalidParameter, op, "no scope id")
	}

	oplogWrapper, err := r.kms.GetWrapper(ctx, cs.ScopeId, kms.KeyPurposeOplog)
	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get oplog wrapper"))
	}

	var rows int
	query, values := cs.softDeleteQuery()
	_, err = r.writer.DoTx(
		ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(_ db.Reader, w db.Writer) (err error) {
			var msgs []*oplog.Message
			ticket, err := w.GetTicket(ctx, cs)
			if err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to get ticket"))
			}

			rows, err = w.Exec(ctx, query, values)
			if err != nil {
				return errors.Wrap(ctx, err, op)
			}
			if rows > 1 {
				return errors.New(ctx, errors.MultipleRecords, op, "more than 1 credential store would have been deleted")
			}
			msg := cs.oplogMessage(db.UpdateOp)
			msg.FieldMaskPaths = []string{"DeleteTime"}
			msgs = append(msgs, msg)

			metadata := cs.oplog(oplog.OpType_OP_TYPE_UPDATE)
			if err := w.WriteOplogEntryWith(ctx, oplogWrapper, ticket, metadata, msgs); err != nil {
				return errors.Wrap(ctx, err, op, errors.WithMsg("unable to write oplog"))
			}

			return nil
		},
	)

	if err != nil {
		return db.NoRowsAffected, errors.Wrap(ctx, err, op, errors.WithMsg(fmt.Sprintf("delete failed for %s", cs.PublicId)))
	}

	if rows > 0 {
		// Schedule token revocation and credential store cleanup jobs to run immediately
		_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, tokenRevocationJobName, 0)
		_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, credentialStoreCleanupJobName, 0)
	}
	return rows, nil
}
