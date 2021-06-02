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
	if cs.clientCert != nil && len(cs.clientCert.CertificateKey) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "client certificate without private key")
	}

	cs = cs.clone()

	id, err := newCredentialStoreId()
	if err != nil {
		return nil, errors.Wrap(err, op)
	}
	cs.PublicId = id
	if cs.clientCert != nil {
		cs.clientCert.StoreId = id
	}

	client, err := cs.client()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to create vault client"))
	}

	tokenLookup, err := client.lookupToken()
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to lookup vault token"))
	}
	if err := validateTokenLookup(op, tokenLookup); err != nil {
		return nil, err
	}
	renewedToken, err := client.renewToken()
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

	// Best effort update next run time of token renewal job, but an error should not
	// cause update to fail.
	// TODO (lcr 05/2021): log error once repo has logger
	_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, tokenRenewalJobName, token.renewalIn())

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

func (r *Repository) lookupPrivateStore(ctx context.Context, publicId string) (*privateStore, error) {
	const op = "vault.(Repository).lookupPrivateStore"
	if publicId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no public id")
	}
	ps := allocPrivateStore()
	if err := r.reader.LookupWhere(ctx, &ps, "public_id = ? and token_status = ?", publicId, StatusCurrent); err != nil {
		if errors.IsNotFoundError(err) {
			return nil, nil
		}
		return nil, errors.Wrap(err, op, errors.WithMsg(fmt.Sprintf("failed for: %s", publicId)))
	}

	databaseWrapper, err := r.kms.GetWrapper(ctx, ps.ScopeId, kms.KeyPurposeDatabase)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
	}

	if err := ps.decrypt(ctx, databaseWrapper); err != nil {
		return nil, errors.Wrap(err, op)
	}

	return ps, nil
}

type privateStore struct {
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
	TokenRenewalTime     *timestamp.Timestamp
	TokenKeyId           string
	TokenStatus          string
	ClientCert           []byte
	ClientKeyId          string
	ClientKey            []byte
	CtClientKey          []byte
	ClientCertKeyHmac    []byte
}

func allocPrivateStore() *privateStore {
	return &privateStore{}
}

func (ps *privateStore) toCredentialStore() *CredentialStore {
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
			return errors.Wrap(err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("token"))
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
			return errors.Wrap(err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("client certificate"))
		}
		ps.ClientKey = pckv.Key
	}
	return nil
}

func (ps *privateStore) client() (*client, error) {
	const op = "vault.(privateStore).client"
	clientConfig := &clientConfig{
		Addr:          ps.VaultAddress,
		Token:         string(ps.Token),
		CaCert:        ps.CaCert,
		TlsServerName: ps.TlsServerName,
		TlsSkipVerify: ps.TlsSkipVerify,
		Namespace:     ps.Namespace,
	}

	if ps.ClientKey != nil {
		clientConfig.ClientCert = ps.ClientCert
		clientConfig.ClientKey = ps.ClientKey
	}

	client, err := newClient(clientConfig)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

// GetPublicId returns the public id.
func (ps *privateStore) GetPublicId() string { return ps.PublicId }

// TableName returns the table name for gorm.
func (ps *privateStore) TableName() string {
	return "credential_vault_store_client_private"
}

// TODO: DO NOT SUBMIT: figure out if these should be in library or store.
const (
	NameField        = "Name"
	DescriptionField = "Description"
)

const (
	certificateField    = "Certificate"
	certificateKeyField = "CertificateKey"
	vaultAddressField   = "VaultAddress"
	namespaceField      = "Namespace"
	caCertField         = "CaCert"
	tlsServerNameField  = "TlsServerName"
	tlsSkipVerifyField  = "TlsSkipVerify"
	tokenField          = "Token"
)

// applyUpdate takes the new and applies it to the orig using the field masks
func applyUpdate(new, orig *CredentialStore, fieldMaskPaths []string) *CredentialStore {
	cp := orig.clone()
	for _, f := range fieldMaskPaths {
		switch f {
		case NameField:
			cp.Name = new.Name
		case DescriptionField:
			cp.Description = new.Description
		case certificateField:
			if new.clientCert == nil {
				cp.clientCert = nil
				continue
			}
			if cp.clientCert == nil {
				cp.clientCert = allocClientCertificate()
			}
			cp.clientCert.Certificate = new.clientCert.GetCertificate()
		case certificateKeyField:
			if new.clientCert == nil {
				cp.clientCert = nil
				continue
			}
			if cp.clientCert == nil {
				cp.clientCert = allocClientCertificate()
			}
			cp.clientCert.CertificateKey = new.clientCert.GetCertificateKey()
		case vaultAddressField:
			cp.VaultAddress = new.VaultAddress
		case namespaceField:
			cp.Namespace = new.Namespace
		case caCertField:
			cp.CaCert = new.CaCert
		case tlsServerNameField:
			cp.TlsServerName = new.TlsServerName
		case tlsSkipVerifyField:
			cp.TlsSkipVerify = new.TlsSkipVerify
		case tokenField:
			cp.inputToken = new.inputToken
		}
	}
	return cp
}

// func updateRequiresVaultConnectionCheck(paths []string) bool {
// 	for _, f := range paths {
// 		switch {
// 		case strings.EqualFold(namespaceField, f),
// 			strings.EqualFold(tlsServerNameField, f),
// 			strings.EqualFold(tlsSkipVerifyField, f),
// 			strings.EqualFold(caCertField, f),
// 			strings.EqualFold(vaultAddressField, f),
// 			strings.EqualFold(certificateField, f),
// 			strings.EqualFold(certificateKeyField, f),
// 			strings.EqualFold(tokenField, f):
// 				return true
// 		}
// 	}
// 	return false
// }

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

	updateToken := false
	for _, f := range fieldMaskPaths {
		switch {
		case strings.EqualFold(NameField, f):
		case strings.EqualFold(descriptionField, f):
		case strings.EqualFold(namespaceField, f):
		case strings.EqualFold(tlsServerNameField, f):
		case strings.EqualFold(tlsSkipVerifyField, f):
		case strings.EqualFold(caCertField, f):
		case strings.EqualFold(vaultAddressField, f):
		case strings.EqualFold(certificateField, f):
		case strings.EqualFold(certificateKeyField, f):
		case strings.EqualFold(tokenField, f):
			if len(cs.inputToken) != 0 {
				updateToken = true
			}
		default:
			return nil, db.NoRowsAffected, errors.New(errors.InvalidFieldMask, op, f)
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
		return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "attempting to unset a required field on a client cert")
	}
	if len(append(dbMask, certDbMask...)) == 0 && len(append(nullFields, certNullFields...)) == 0 {
		return nil, db.NoRowsAffected, errors.New(errors.EmptyFieldMask, op, "missing field mask")
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
			return nil, db.NoRowsAffected, errors.New(errors.InvalidParameter, op, "attempting to unset the value for token")
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

	ps, err := r.lookupPrivateStore(ctx, cs.GetPublicId())
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to lookup private credential store"))
	}
	if ps == nil {
		// Return nil error and no rows affected indicates the resource cannot be found.
		return nil, db.NoRowsAffected, nil
	}
	updatedStore := applyUpdate(ps.toCredentialStore(), cs, fieldMaskPaths)
	client, err := updatedStore.client()
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("unable to get client for updated store"))
	}
	tokenLookup, err := client.lookupToken()
	if err != nil {
		return nil, db.NoRowsAffected, errors.Wrap(err, op, errors.WithMsg("cannot lookup token for updated store"))
	}
	if err := validateTokenLookup(op, tokenLookup); err != nil {
		return nil, db.NoRowsAffected, err
	}

	var rowsUpdated int
	var returnedCredentialStore *CredentialStore
	_, err = r.writer.DoTx(ctx, db.StdRetryCnt, db.ExpBackoff{},
		func(reader db.Reader, w db.Writer) error {
			msgs := make([]*oplog.Message, 0, 3)
			ticket, err := w.GetTicket(cs)
			if err != nil {
				return errors.Wrap(err, op, errors.WithMsg("unable to get ticket"))
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
					return errors.Wrap(err, op, errors.WithMsg("unable to update credential store version"))
				}
				switch rowsUpdated {
				case 1:
				case 0:
					return nil
				default:
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated credential store version and %d rows updated", rowsUpdated))
				}
			default:
				rowsUpdated, err = w.Update(ctx, cs, filteredDbMask, filteredNullFields, db.NewOplogMsg(&csOplogMsg), db.WithVersion(&version))
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to update credential store"))
				}
				switch rowsUpdated {
				case 1:
				case 0:
					return nil
				default:
					return errors.New(errors.MultipleRecords, op, fmt.Sprintf("updated credential store and %d rows updated", rowsUpdated))
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
					return errors.Wrap(err, op, errors.WithMsg("unable to delete client certificate"))
				}
				if rows > 1 {
					return errors.New(errors.MultipleRecords, op, "more than 1 client certificate would have been deleted")
				}
				msgs = append(msgs, deleteCert.oplogMessage(db.DeleteOp))
			case len(certDbMask) > 0:
				if updatedStore.clientCert == nil {
					return errors.New(errors.InvalidParameter, op, "updated cert")
				}
				updatedStore.clientCert.encrypt(ctx, databaseWrapper)
				query, values := updatedStore.clientCert.insertQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to upsert client certificate"))
				}
				if rows > 1 {
					return errors.New(errors.MultipleRecords, op, "more than 1 client certificate would have been upserted")
				}
			}

			if updateToken {
				renewedToken, err := client.renewToken()
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to renew vault token"))
				}
				tokenExpires, err := renewedToken.TokenTTL()
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to get vault token expiration"))
				}
				accessor, err := renewedToken.TokenAccessor()
				if err != nil {
					return errors.Wrap(err, op, errors.WithMsg("unable to get vault token accessor"))
				}
				token, err := newToken(cs.GetPublicId(), cs.inputToken, []byte(accessor), tokenExpires)
				if err != nil {
					return err
				}
				// encrypt token
				if err := token.encrypt(ctx, databaseWrapper); err != nil {
					return errors.Wrap(err, op)
				}
				query, values := token.insertQuery()
				rows, err := w.Exec(ctx, query, values)
				if err != nil {
					return errors.Wrap(err, op)
				}
				if rows > 1 {
					return errors.New(errors.MultipleRecords, op, "more than 1 token would have been created")
				}
				msgs = append(msgs, token.oplogMessage(db.CreateOp))
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

	if updateToken {
		// Best effort update next run time of token renewal job, but an error should not
		// cause update to fail.
		// TODO (lcr 05/2021): log error once repo has logger
		_ = r.scheduler.UpdateJobNextRunInAtLeast(ctx, tokenRenewalJobName, token.renewalIn())
	}

	if err != nil {
		if errors.IsUniqueError(err) {
			return nil, db.NoRowsAffected, errors.New(errors.NotUnique, op,
				fmt.Sprintf("name %s already exists: %s", cs.Name, cs.PublicId))
		}
		return nil, db.NoRowsAffected, err
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
