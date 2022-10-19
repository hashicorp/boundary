package vault

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/internal/sshprivatekey"
	"github.com/hashicorp/boundary/internal/credential/vault/internal/usernamepassword"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/util/template"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	vault "github.com/hashicorp/vault/api"
	"google.golang.org/protobuf/proto"
)

var _ credential.Dynamic = (*baseCred)(nil)

type baseCred struct {
	*Credential

	lib        *issueCredentialLibrary
	secretData map[string]interface{}
}

func (bc *baseCred) Secret() credential.SecretData { return bc.secretData }
func (bc *baseCred) Library() credential.Library   { return bc.lib }
func (bc *baseCred) Purpose() credential.Purpose   { return bc.lib.Purpose }
func (bc *baseCred) getExpiration() time.Duration  { return bc.expiration }

// convert converts bc to a specific credential type if bc is not
// UnspecifiedType.
func convert(ctx context.Context, bc *baseCred) (dynamicCred, error) {
	switch bc.Library().CredentialType() {
	case credential.UsernamePasswordType:
		return baseToUsrPass(ctx, bc)
	case credential.SshPrivateKeyType:
		return baseToSshPriKey(ctx, bc)
	}
	return bc, nil
}

var _ credential.UsernamePassword = (*usrPassCred)(nil)

type usrPassCred struct {
	*baseCred
	username string
	password credential.Password
}

func (c *usrPassCred) Username() string              { return c.username }
func (c *usrPassCred) Password() credential.Password { return c.password }

func baseToUsrPass(ctx context.Context, bc *baseCred) (*usrPassCred, error) {
	switch {
	case bc == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred"))
	case bc.lib == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred.lib"))
	case bc.Library().CredentialType() != credential.UsernamePasswordType:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("invalid credential type"))
	}

	uAttr, pAttr := bc.lib.UsernameAttribute, bc.lib.PasswordAttribute
	if uAttr == "" {
		uAttr = "username"
	}
	if pAttr == "" {
		pAttr = "password"
	}
	username, password := usernamepassword.Extract(bc.secretData, uAttr, pAttr)
	if username == "" || password == "" {
		return nil, errors.E(ctx, errors.WithCode(errors.VaultInvalidCredentialMapping))
	}

	return &usrPassCred{
		baseCred: bc,
		username: username,
		password: credential.Password(password),
	}, nil
}

var _ credential.SshPrivateKey = (*sshPrivateKeyCred)(nil)

type sshPrivateKeyCred struct {
	*baseCred
	username   string
	privateKey credential.PrivateKey
	passphrase []byte
}

func (c *sshPrivateKeyCred) Username() string                  { return c.username }
func (c *sshPrivateKeyCred) PrivateKey() credential.PrivateKey { return c.privateKey }
func (c *sshPrivateKeyCred) PrivateKeyPassphrase() []byte      { return c.passphrase }

func baseToSshPriKey(ctx context.Context, bc *baseCred) (*sshPrivateKeyCred, error) {
	switch {
	case bc == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred"))
	case bc.lib == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred.lib"))
	case bc.Library().CredentialType() != credential.SshPrivateKeyType:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("invalid credential type"))
	}

	uAttr, pkAttr, pAttr := bc.lib.UsernameAttribute, bc.lib.PrivateKeyAttribute, bc.lib.PrivateKeyPassphraseAttribute
	if uAttr == "" {
		uAttr = "username"
	}
	if pkAttr == "" {
		pkAttr = "private_key"
	}
	if pAttr == "" {
		pAttr = "private_key_passphrase"
	}
	username, pk, pass := sshprivatekey.Extract(bc.secretData, uAttr, pkAttr, pAttr)
	if username == "" || pk == nil {
		return nil, errors.E(ctx, errors.WithCode(errors.VaultInvalidCredentialMapping))
	}

	return &sshPrivateKeyCred{
		baseCred:   bc,
		username:   username,
		privateKey: pk,
		passphrase: pass,
	}, nil
}

var _ credential.Library = (*issueCredentialLibrary)(nil)

// A issueCredentialLibrary contains all the values needed to connect to Vault and
// retrieve credentials.
type issueCredentialLibrary struct {
	PublicId                      string `gorm:"primary_key"`
	StoreId                       string
	Name                          string
	Description                   string
	CreateTime                    *timestamp.Timestamp
	UpdateTime                    *timestamp.Timestamp
	Version                       uint32
	VaultPath                     string
	HttpMethod                    string
	HttpRequestBody               []byte
	CredType                      string `gorm:"column:credential_type"`
	ProjectId                     string
	VaultAddress                  string
	Namespace                     string
	CaCert                        []byte
	TlsServerName                 string
	TlsSkipVerify                 bool
	WorkerFilter                  string
	Token                         TokenSecret
	CtToken                       []byte
	TokenHmac                     []byte
	TokenKeyId                    string
	ClientCert                    []byte
	ClientKey                     KeySecret
	CtClientKey                   []byte
	ClientKeyId                   string
	UsernameAttribute             string
	PasswordAttribute             string
	PrivateKeyAttribute           string
	PrivateKeyPassphraseAttribute string
	Purpose                       credential.Purpose `gorm:"-"`
}

func (pl *issueCredentialLibrary) clone() *issueCredentialLibrary {
	// The 'append(a[:0:0], a...)' comes from
	// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
	return &issueCredentialLibrary{
		PublicId:                      pl.PublicId,
		StoreId:                       pl.StoreId,
		CredType:                      pl.CredType,
		UsernameAttribute:             pl.UsernameAttribute,
		PasswordAttribute:             pl.PasswordAttribute,
		PrivateKeyAttribute:           pl.PrivateKeyAttribute,
		PrivateKeyPassphraseAttribute: pl.PrivateKeyPassphraseAttribute,
		Name:                          pl.Name,
		Description:                   pl.Description,
		CreateTime:                    proto.Clone(pl.CreateTime).(*timestamp.Timestamp),
		UpdateTime:                    proto.Clone(pl.UpdateTime).(*timestamp.Timestamp),
		Version:                       pl.Version,
		ProjectId:                     pl.ProjectId,
		VaultPath:                     pl.VaultPath,
		HttpMethod:                    pl.HttpMethod,
		HttpRequestBody:               append(pl.HttpRequestBody[:0:0], pl.HttpRequestBody...),
		VaultAddress:                  pl.VaultAddress,
		Namespace:                     pl.Namespace,
		CaCert:                        append(pl.CaCert[:0:0], pl.CaCert...),
		TlsServerName:                 pl.TlsServerName,
		TlsSkipVerify:                 pl.TlsSkipVerify,
		WorkerFilter:                  pl.WorkerFilter,
		TokenHmac:                     append(pl.TokenHmac[:0:0], pl.TokenHmac...),
		Token:                         append(pl.Token[:0:0], pl.Token...),
		CtToken:                       append(pl.CtToken[:0:0], pl.CtToken...),
		TokenKeyId:                    pl.TokenKeyId,
		ClientCert:                    append(pl.ClientCert[:0:0], pl.ClientCert...),
		ClientKey:                     append(pl.ClientKey[:0:0], pl.ClientKey...),
		CtClientKey:                   append(pl.CtClientKey[:0:0], pl.CtClientKey...),
		ClientKeyId:                   pl.ClientKeyId,
		Purpose:                       pl.Purpose,
	}
}

func (pl *issueCredentialLibrary) GetPublicId() string                 { return pl.PublicId }
func (pl *issueCredentialLibrary) GetStoreId() string                  { return pl.StoreId }
func (pl *issueCredentialLibrary) GetName() string                     { return pl.Name }
func (pl *issueCredentialLibrary) GetDescription() string              { return pl.Description }
func (pl *issueCredentialLibrary) GetVersion() uint32                  { return pl.Version }
func (pl *issueCredentialLibrary) GetCreateTime() *timestamp.Timestamp { return pl.CreateTime }
func (pl *issueCredentialLibrary) GetUpdateTime() *timestamp.Timestamp { return pl.UpdateTime }

func (pl *issueCredentialLibrary) CredentialType() credential.Type {
	switch ct := pl.CredType; ct {
	case "":
		return credential.UnspecifiedType
	default:
		return credential.Type(ct)
	}
}

func (pl *issueCredentialLibrary) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(issueCredentialLibrary).decrypt"

	if pl.CtToken != nil {
		type ptk struct {
			Token   []byte `wrapping:"pt,token_data"`
			CtToken []byte `wrapping:"ct,token_data"`
		}
		ptkv := &ptk{
			CtToken: pl.CtToken,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, ptkv, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("token"))
		}
		pl.Token = ptkv.Token
	}

	if pl.CtClientKey != nil && pl.ClientCert != nil {
		type pck struct {
			Key   []byte `wrapping:"pt,key_data"`
			CtKey []byte `wrapping:"ct,key_data"`
		}
		pckv := &pck{
			CtKey: pl.CtClientKey,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, pckv, nil); err != nil {
			return errors.Wrap(ctx, err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("client certificate"))
		}
		pl.ClientKey = pckv.Key
	}
	return nil
}

func (pl *issueCredentialLibrary) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(issueCredentialLibrary).client"
	clientConfig := &clientConfig{
		Addr:          pl.VaultAddress,
		Token:         pl.Token,
		CaCert:        pl.CaCert,
		TlsServerName: pl.TlsServerName,
		TlsSkipVerify: pl.TlsSkipVerify,
		Namespace:     pl.Namespace,
	}

	if pl.ClientKey != nil {
		clientConfig.ClientCert = pl.ClientCert
		clientConfig.ClientKey = pl.ClientKey
	}

	client, err := vaultClientFactoryFn(ctx, clientConfig, WithWorkerFilter(pl.WorkerFilter))
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

type dynamicCred interface {
	credential.Dynamic
	getExpiration() time.Duration
	insertQuery() (query string, queryValues []interface{})
	updateSessionQuery(purpose credential.Purpose) (query string, queryValues []interface{})
}

// retrieveCredential retrieves a dynamic credential from Vault for the
// given sessionId.
//
// Supported options: credential.WithTemplateData
func (pl *issueCredentialLibrary) retrieveCredential(ctx context.Context, op errors.Op, sessionId string, opt ...credential.Option) (dynamicCred, error) {
	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// Get the credential ID early. No need to get a secret from Vault
	// if there is no way to save it in the database.
	credId, err := newCredentialId()
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	client, err := pl.client(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var secret *vault.Secret
	var reqErr error
	switch Method(pl.HttpMethod) {
	case MethodGet:
		secret, reqErr = client.get(ctx, pl.VaultPath)
	case MethodPost:
		body := string(pl.HttpRequestBody)
		if body != "" {
			parsedTmpl, err := template.New(ctx, string(pl.HttpRequestBody))
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
			body, err = parsedTmpl.Generate(ctx, opts.WithTemplateData)
			if err != nil {
				return nil, errors.Wrap(ctx, err, op)
			}
		}
		secret, reqErr = client.post(ctx, pl.VaultPath, []byte(body))
	default:
		return nil, errors.New(ctx, errors.Internal, op, fmt.Sprintf("unknown http method: library: %s", pl.PublicId))
	}

	if reqErr != nil {
		// TODO(mgaffney) 05/2021: detect if the error is because of an
		// expired or invalid token
		return nil, errors.Wrap(ctx, reqErr, op)
	}
	if secret == nil {
		return nil, errors.E(ctx, errors.WithCode(errors.VaultEmptySecret), errors.WithOp(op))
	}

	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second
	cred, err := newCredential(pl.GetPublicId(), sessionId, secret.LeaseID, pl.TokenHmac, leaseDuration)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cred.PublicId = credId
	cred.IsRenewable = secret.Renewable

	dCred := &baseCred{
		Credential: cred,
		lib:        pl,
		secretData: secret.Data,
	}
	return convert(ctx, dCred)
}

// TableName returns the table name for gorm.
func (pl *issueCredentialLibrary) TableName() string {
	return "credential_vault_library_issue_credentials"
}

func (r *Repository) getIssueCredLibraries(ctx context.Context, requests []credential.Request) ([]*issueCredentialLibrary, error) {
	const op = "vault.(Repository).getIssueCredLibraries"

	mapper, err := newMapper(requests)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	libIds := mapper.libIds()
	var inClauseSpots []string
	for i := 1; i < len(libIds)+1; i++ {
		inClauseSpots = append(inClauseSpots, fmt.Sprintf("@%d", i))
	}
	inClause := strings.Join(inClauseSpots, ",")

	query := fmt.Sprintf(selectLibrariesQuery, inClause)

	var params []interface{}
	for idx, v := range libIds {
		params = append(params, sql.Named(fmt.Sprintf("%d", idx+1), v))
	}
	rows, err := r.reader.Query(ctx, query, params)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("query failed"))
	}
	defer rows.Close()

	var libs []*issueCredentialLibrary
	for rows.Next() {
		var lib issueCredentialLibrary
		if err := r.reader.ScanRows(ctx, rows, &lib); err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("scan row failed"))
		}
		purps := mapper.get(lib.GetPublicId())
		if len(purps) == 0 {
			return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("unknown library"))
		}
		for _, purp := range purps {
			cp := lib.clone()
			cp.Purpose = purp
			libs = append(libs, cp)
		}
	}

	for _, pl := range libs {
		databaseWrapper, err := r.kms.GetWrapper(ctx, pl.ProjectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}

		if err := pl.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	return libs, nil
}

// requestMap takes a slice of credential requests and provides of list of
// library IDs with duplicate IDs removed. It also provides a way to lookup
// the list of credential purposes for a particular library ID.
//
// A single library can be used to retrieve multiple credentials as long as
// each credential is for a different purpose. When retrieving the private
// libraries from the database, a list of library IDs with duplicates
// removed is needed. When requesting credentials from vault, any library
// being used for multiple purposes needs to be duplicated with the purpose
// so multiple requests are made to vault using the same library.
type requestMap struct {
	ids map[string][]credential.Purpose
}

func newMapper(requests []credential.Request) (*requestMap, error) {
	ids := make(map[string][]credential.Purpose, len(requests))
	for _, req := range requests {
		if purps, ok := ids[req.SourceId]; ok {
			for _, purp := range purps {
				if purp == req.Purpose {
					return nil, errors.EDeprecated(errors.WithCode(errors.InvalidParameter), errors.WithMsg("duplicate library and purpose"))
				}
			}
		}
		ids[req.SourceId] = append(ids[req.SourceId], req.Purpose)
	}
	return &requestMap{
		ids: ids,
	}, nil
}

func (m *requestMap) libIds() []string {
	var ids []string
	for id := range m.ids {
		ids = append(ids, id)
	}
	return ids
}

func (m *requestMap) get(libraryId string) []credential.Purpose {
	return m.ids[libraryId]
}
