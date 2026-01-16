// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"
	"time"

	ldapv3 "github.com/go-ldap/ldap/v3"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/internal/password"
	"github.com/hashicorp/boundary/internal/credential/vault/internal/sshprivatekey"
	"github.com/hashicorp/boundary/internal/credential/vault/internal/usernamepassword"
	"github.com/hashicorp/boundary/internal/credential/vault/internal/usernamepassworddomain"
	"github.com/hashicorp/boundary/internal/db/sentinel"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/hashicorp/boundary/internal/util/template"
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
	"github.com/hashicorp/go-kms-wrapping/v2/extras/structwrapping"
	vault "github.com/hashicorp/vault/api"
	"github.com/mikesmitty/edkey"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/proto"
)

var _ credential.Dynamic = (*baseCred)(nil)

type baseCred struct {
	*Credential

	lib        issuingCredentialLibrary
	secretData map[string]any
}

func (bc *baseCred) Secret() credential.SecretData { return bc.secretData }
func (bc *baseCred) Library() credential.Library   { return bc.lib }
func (bc *baseCred) Purpose() credential.Purpose   { return bc.lib.GetPurpose() }
func (bc *baseCred) getExpiration() time.Duration  { return bc.expiration }
func (bc *baseCred) getCredential() *Credential    { return bc.Credential }
func (bc *baseCred) isRevokable() bool             { return bc.ExternalId != sentinel.ExternalIdNone }

// convert converts bc to a specific credential type if bc is not
// UnspecifiedType.
func convert(ctx context.Context, bc *baseCred) (dynamicCred, error) {
	switch bc.Library().CredentialType() {
	case globals.UsernamePasswordCredentialType:
		return baseToUsrPass(ctx, bc)
	case globals.SshPrivateKeyCredentialType:
		return baseToSshPriKey(ctx, bc)
	case globals.UsernamePasswordDomainCredentialType:
		return baseToUsrPassDomain(ctx, bc)
	case globals.PasswordCredentialType:
		return baseToPass(ctx, bc)
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
	case bc.Library().CredentialType() != globals.UsernamePasswordCredentialType:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("invalid credential type"))
	}

	lib, ok := bc.lib.(*genericIssuingCredentialLibrary)
	if !ok {
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("baseCred.lib is not of type genericIssuingCredentialLibrary"))
	}

	uAttr, pAttr := lib.UsernameAttribute, lib.PasswordAttribute
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

var _ credential.UsernamePasswordDomain = (*usrPassDomainCred)(nil)

type usrPassDomainCred struct {
	*baseCred
	username string
	password credential.Password
	domain   string
}

func (c *usrPassDomainCred) Username() string              { return c.username }
func (c *usrPassDomainCred) Password() credential.Password { return c.password }
func (c *usrPassDomainCred) Domain() string                { return c.domain }

func baseToUsrPassDomain(ctx context.Context, bc *baseCred) (*usrPassDomainCred, error) {
	switch {
	case bc == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred"))
	case bc.lib == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred.lib"))
	case bc.Library().CredentialType() != globals.UsernamePasswordDomainCredentialType:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("invalid credential type"))
	}

	lib, ok := bc.lib.(*genericIssuingCredentialLibrary)
	if !ok {
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("baseCred.lib is not of type genericIssuingCredentialLibrary"))
	}

	uAttr, pAttr, dAttr := lib.UsernameAttribute, lib.PasswordAttribute, lib.DomainAttribute
	if uAttr == "" {
		uAttr = "username"
	}
	if pAttr == "" {
		pAttr = "password"
	}
	if dAttr == "" {
		dAttr = "domain"
	}
	username, password, domain := usernamepassworddomain.Extract(bc.secretData, uAttr, pAttr, dAttr)
	if username == "" || password == "" || domain == "" {
		return nil, errors.E(ctx, errors.WithCode(errors.VaultInvalidCredentialMapping))
	}

	return &usrPassDomainCred{
		baseCred: bc,
		username: username,
		password: credential.Password(password),
		domain:   domain,
	}, nil
}

var _ credential.PasswordOnly = (*passCred)(nil)

type passCred struct {
	*baseCred
	password credential.Password
}

func (c *passCred) Password() credential.Password { return c.password }

func baseToPass(ctx context.Context, bc *baseCred) (*passCred, error) {
	switch {
	case bc == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred"))
	case bc.lib == nil:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("nil baseCred.lib"))
	case bc.Library().CredentialType() != globals.PasswordCredentialType:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("invalid credential type"))
	}

	lib, ok := bc.lib.(*genericIssuingCredentialLibrary)
	if !ok {
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("baseCred.lib is not of type genericIssuingCredentialLibrary"))
	}

	pAttr := lib.PasswordAttribute
	if pAttr == "" {
		pAttr = "password"
	}
	password := password.Extract(bc.secretData, pAttr)
	if password == "" {
		return nil, errors.E(ctx, errors.WithCode(errors.VaultInvalidCredentialMapping))
	}

	return &passCred{
		baseCred: bc,
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
	case bc.Library().CredentialType() != globals.SshPrivateKeyCredentialType:
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("invalid credential type"))
	}

	lib, ok := bc.lib.(*genericIssuingCredentialLibrary)
	if !ok {
		return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("baseCred.lib is not of type genericIssuingCredentialLibrary"))
	}

	uAttr, pkAttr, pAttr := lib.UsernameAttribute, lib.PrivateKeyAttribute, lib.PrivateKeyPassphraseAttribute
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

type sshCertCred struct {
	*sshPrivateKeyCred
	certificate []byte
}

func (c *sshCertCred) Certificate() []byte { return c.certificate }

var _ credential.Library = (*genericIssuingCredentialLibrary)(nil)

type issuingCredentialLibrary interface {
	credential.Library
	GetPurpose() credential.Purpose
	retrieveCredential(context.Context, errors.Op, ...credential.Option) (dynamicCred, error)
}

// genericIssuingCredentialLibrary is a subtype of
// privateCredentialLibraryAllTypes specifically for Vault generic credential
// libraries. It contains all the values needed to connect to Vault and retrieve
// credentials.
type genericIssuingCredentialLibrary struct {
	PublicId                      string
	StoreId                       string
	Name                          string
	Description                   string
	CreateTime                    *timestamp.Timestamp
	UpdateTime                    *timestamp.Timestamp
	Version                       uint32
	VaultPath                     string
	HttpMethod                    string
	HttpRequestBody               []byte
	CredType                      string
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
	DomainAttribute               string
	PrivateKeyAttribute           string
	PrivateKeyPassphraseAttribute string
	Purpose                       credential.Purpose
	AdditionalValidPrincipals     string
}

func (pl *genericIssuingCredentialLibrary) clone() *genericIssuingCredentialLibrary {
	// The 'append(a[:0:0], a...)' comes from
	// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
	return &genericIssuingCredentialLibrary{
		PublicId:                      pl.PublicId,
		StoreId:                       pl.StoreId,
		CredType:                      pl.CredType,
		UsernameAttribute:             pl.UsernameAttribute,
		PasswordAttribute:             pl.PasswordAttribute,
		DomainAttribute:               pl.DomainAttribute,
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

func (pl *genericIssuingCredentialLibrary) GetPublicId() string                 { return pl.PublicId }
func (pl *genericIssuingCredentialLibrary) GetStoreId() string                  { return pl.StoreId }
func (pl *genericIssuingCredentialLibrary) GetName() string                     { return pl.Name }
func (pl *genericIssuingCredentialLibrary) GetDescription() string              { return pl.Description }
func (pl *genericIssuingCredentialLibrary) GetVersion() uint32                  { return pl.Version }
func (pl *genericIssuingCredentialLibrary) GetCreateTime() *timestamp.Timestamp { return pl.CreateTime }
func (pl *genericIssuingCredentialLibrary) GetUpdateTime() *timestamp.Timestamp { return pl.UpdateTime }
func (pl *genericIssuingCredentialLibrary) GetPurpose() credential.Purpose      { return pl.Purpose }

func (pl *genericIssuingCredentialLibrary) CredentialType() globals.CredentialType {
	switch ct := pl.CredType; ct {
	case "":
		return globals.UnspecifiedCredentialType
	default:
		return globals.CredentialType(ct)
	}
}

// GetResourceType returns the resource type of the CredentialLibrary
func (pl *genericIssuingCredentialLibrary) GetResourceType() resource.Type {
	return resource.CredentialLibrary
}

func (pl *genericIssuingCredentialLibrary) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(genericIssuingCredentialLibrary).client"
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
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

type dynamicCred interface {
	credential.Dynamic
	getExpiration() time.Duration
	getCredential() *Credential
	isRevokable() bool
}

// retrieveCredential retrieves a dynamic credential from Vault for the
// given sessionId.
//
// Supported options: credential.WithTemplateData
func (pl *genericIssuingCredentialLibrary) retrieveCredential(ctx context.Context, op errors.Op, opt ...credential.Option) (dynamicCred, error) {
	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// Get the credential ID early. No need to get a secret from Vault
	// if there is no way to save it in the database.
	credId, err := newCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	client, err := pl.client(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	var secret *vault.Secret
	var reqErr error

	// Template the path
	path := pl.VaultPath
	if path != "" {
		parsedTmpl, err := template.New(ctx, path)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		path, err = parsedTmpl.Generate(ctx, opts.WithTemplateData)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	// Template the body
	body := string(pl.HttpRequestBody)
	if body != "" {
		parsedTmpl, err := template.New(ctx, body)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		body, err = parsedTmpl.Generate(ctx, opts.WithTemplateData)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	switch Method(pl.HttpMethod) {
	case MethodGet:
		secret, reqErr = client.get(ctx, path)
	case MethodPost:
		secret, reqErr = client.post(ctx, path, []byte(body))
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
	cred, err := newCredential(ctx, pl.GetPublicId(), secret.LeaseID, pl.TokenHmac, leaseDuration)
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

func (r *Repository) getIssueCredLibraries(ctx context.Context, requests []credential.Request) ([]issuingCredentialLibrary, error) {
	const op = "vault.(Repository).getIssueCredLibraries"

	mapper, err := newMapper(ctx, requests)
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

	var params []any
	for idx, v := range libIds {
		params = append(params, sql.Named(fmt.Sprintf("%d", idx+1), v))
	}
	rows, err := r.reader.Query(ctx, query, params)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("query failed"))
	}
	defer rows.Close()

	var libs []*privateCredentialLibraryAllTypes
	for rows.Next() {
		var lib privateCredentialLibraryAllTypes
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
	if err := rows.Err(); err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("next row failed"))
	}

	var decryptedLibs []issuingCredentialLibrary
	for _, pl := range libs {
		databaseWrapper, err := r.kms.GetWrapper(ctx, pl.ProjectId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to get database wrapper"))
		}

		if err := pl.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		decryptedLibs = append(decryptedLibs, pl.toTypedIssuingCredentialLibrary())
	}

	return decryptedLibs, nil
}

// privateCredentialLibraryAllTypes is a type that interfaces with the database.
// It contains all the values needed to connect to Vault and retrieve
// credentials.
type privateCredentialLibraryAllTypes struct {
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
	DomainAttribute               string
	PrivateKeyAttribute           string
	PrivateKeyPassphraseAttribute string
	Purpose                       credential.Purpose `gorm:"-"`
	KeyType                       string
	KeyBits                       int
	Username                      string
	Ttl                           string
	KeyId                         string
	CriticalOptions               []byte
	Extensions                    []byte
	CredLibType                   string
	AdditionalValidPrincipals     string
}

func (pl *privateCredentialLibraryAllTypes) GetPublicId() string { return pl.PublicId }

// GetResourceType returns the resource type of the CredentialLibrary
func (pl *privateCredentialLibraryAllTypes) GetResourceType() resource.Type {
	return resource.CredentialLibrary
}

func (pl *privateCredentialLibraryAllTypes) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(privateCredentialLibraryAllTypes).decrypt"

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

func (pl *privateCredentialLibraryAllTypes) clone() *privateCredentialLibraryAllTypes {
	// The 'append(a[:0:0], a...)' comes from
	// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
	return &privateCredentialLibraryAllTypes{
		PublicId:                      pl.PublicId,
		StoreId:                       pl.StoreId,
		CredType:                      pl.CredType,
		UsernameAttribute:             pl.UsernameAttribute,
		PasswordAttribute:             pl.PasswordAttribute,
		DomainAttribute:               pl.DomainAttribute,
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
		KeyType:                       pl.KeyType,
		KeyBits:                       pl.KeyBits,
		Username:                      pl.Username,
		Ttl:                           pl.Ttl,
		KeyId:                         pl.KeyId,
		CriticalOptions:               pl.CriticalOptions,
		Extensions:                    pl.Extensions,
		CredLibType:                   pl.CredLibType,
		AdditionalValidPrincipals:     pl.AdditionalValidPrincipals,
	}
}

func (pl *privateCredentialLibraryAllTypes) toTypedIssuingCredentialLibrary() issuingCredentialLibrary {
	switch pl.CredLibType {
	case "ssh-signed-cert":
		return &sshCertIssuingCredentialLibrary{
			PublicId:                  pl.PublicId,
			StoreId:                   pl.StoreId,
			CredType:                  pl.CredType,
			Username:                  pl.Username,
			Name:                      pl.Name,
			Description:               pl.Description,
			CreateTime:                pl.CreateTime,
			UpdateTime:                pl.UpdateTime,
			Version:                   pl.Version,
			ProjectId:                 pl.ProjectId,
			VaultPath:                 pl.VaultPath,
			VaultAddress:              pl.VaultAddress,
			Namespace:                 pl.Namespace,
			CaCert:                    pl.CaCert,
			TlsServerName:             pl.TlsServerName,
			TlsSkipVerify:             pl.TlsSkipVerify,
			WorkerFilter:              pl.WorkerFilter,
			TokenHmac:                 pl.TokenHmac,
			Token:                     pl.Token,
			CtToken:                   pl.CtToken,
			TokenKeyId:                pl.TokenKeyId,
			ClientCert:                pl.ClientCert,
			ClientKey:                 pl.ClientKey,
			CtClientKey:               pl.CtClientKey,
			ClientKeyId:               pl.ClientKeyId,
			Purpose:                   pl.Purpose,
			KeyType:                   pl.KeyType,
			KeyBits:                   pl.KeyBits,
			Ttl:                       pl.Ttl,
			KeyId:                     pl.KeyId,
			CriticalOptions:           pl.CriticalOptions,
			Extensions:                pl.Extensions,
			AdditionalValidPrincipals: pl.AdditionalValidPrincipals,
		}
	case "ldap":
		return &ldapIssuingCredentialLibrary{
			PublicId:                  pl.PublicId,
			StoreId:                   pl.StoreId,
			CredType:                  pl.CredType,
			Username:                  pl.Username,
			Name:                      pl.Name,
			Description:               pl.Description,
			CreateTime:                pl.CreateTime,
			UpdateTime:                pl.UpdateTime,
			Version:                   pl.Version,
			ProjectId:                 pl.ProjectId,
			VaultPath:                 pl.VaultPath,
			VaultAddress:              pl.VaultAddress,
			Namespace:                 pl.Namespace,
			CaCert:                    pl.CaCert,
			TlsServerName:             pl.TlsServerName,
			TlsSkipVerify:             pl.TlsSkipVerify,
			WorkerFilter:              pl.WorkerFilter,
			TokenHmac:                 pl.TokenHmac,
			Token:                     pl.Token,
			CtToken:                   pl.CtToken,
			TokenKeyId:                pl.TokenKeyId,
			ClientCert:                pl.ClientCert,
			ClientKey:                 pl.ClientKey,
			CtClientKey:               pl.CtClientKey,
			ClientKeyId:               pl.ClientKeyId,
			Purpose:                   pl.Purpose,
			KeyType:                   pl.KeyType,
			KeyBits:                   pl.KeyBits,
			Ttl:                       pl.Ttl,
			KeyId:                     pl.KeyId,
			CriticalOptions:           pl.CriticalOptions,
			Extensions:                pl.Extensions,
			AdditionalValidPrincipals: pl.AdditionalValidPrincipals,
		}
	default:
		return &genericIssuingCredentialLibrary{
			PublicId:                      pl.PublicId,
			StoreId:                       pl.StoreId,
			CredType:                      pl.CredType,
			UsernameAttribute:             pl.UsernameAttribute,
			PasswordAttribute:             pl.PasswordAttribute,
			DomainAttribute:               pl.DomainAttribute,
			PrivateKeyAttribute:           pl.PrivateKeyAttribute,
			PrivateKeyPassphraseAttribute: pl.PrivateKeyPassphraseAttribute,
			Name:                          pl.Name,
			Description:                   pl.Description,
			CreateTime:                    pl.CreateTime,
			UpdateTime:                    pl.UpdateTime,
			Version:                       pl.Version,
			ProjectId:                     pl.ProjectId,
			VaultPath:                     pl.VaultPath,
			HttpMethod:                    pl.HttpMethod,
			HttpRequestBody:               pl.HttpRequestBody,
			VaultAddress:                  pl.VaultAddress,
			Namespace:                     pl.Namespace,
			CaCert:                        pl.CaCert,
			TlsServerName:                 pl.TlsServerName,
			TlsSkipVerify:                 pl.TlsSkipVerify,
			WorkerFilter:                  pl.WorkerFilter,
			TokenHmac:                     pl.TokenHmac,
			Token:                         pl.Token,
			CtToken:                       pl.CtToken,
			TokenKeyId:                    pl.TokenKeyId,
			ClientCert:                    pl.ClientCert,
			ClientKey:                     pl.ClientKey,
			CtClientKey:                   pl.CtClientKey,
			ClientKeyId:                   pl.ClientKeyId,
			Purpose:                       pl.Purpose,
			AdditionalValidPrincipals:     pl.AdditionalValidPrincipals,
		}
	}
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

func newMapper(ctx context.Context, requests []credential.Request) (*requestMap, error) {
	ids := make(map[string][]credential.Purpose, len(requests))
	for _, req := range requests {
		if purps, ok := ids[req.SourceId]; ok {
			for _, purp := range purps {
				if purp == req.Purpose {
					return nil, errors.E(ctx, errors.WithCode(errors.InvalidParameter), errors.WithMsg("duplicate library and purpose"))
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

// sshCertIssuingCredentialLibrary is a subtype of
// privateCredentialLibraryAllTypes specifically for Vault SSH Certificate
// credential libraries. It contains all the values needed to connect to Vault
// and retrieve credentials.
type sshCertIssuingCredentialLibrary struct {
	PublicId                  string
	StoreId                   string
	Name                      string
	Description               string
	CreateTime                *timestamp.Timestamp
	UpdateTime                *timestamp.Timestamp
	Version                   uint32
	VaultPath                 string
	CredType                  string
	ProjectId                 string
	VaultAddress              string
	Namespace                 string
	CaCert                    []byte
	TlsServerName             string
	TlsSkipVerify             bool
	WorkerFilter              string
	Token                     TokenSecret
	CtToken                   []byte
	TokenHmac                 []byte
	TokenKeyId                string
	ClientCert                []byte
	ClientKey                 KeySecret
	CtClientKey               []byte
	ClientKeyId               string
	Username                  string
	KeyType                   string
	KeyBits                   int
	KeyId                     string
	Ttl                       string
	CriticalOptions           []byte
	Extensions                []byte
	Purpose                   credential.Purpose
	AdditionalValidPrincipals string
}

func (lib *sshCertIssuingCredentialLibrary) GetPublicId() string            { return lib.PublicId }
func (lib *sshCertIssuingCredentialLibrary) GetStoreId() string             { return lib.StoreId }
func (lib *sshCertIssuingCredentialLibrary) GetName() string                { return lib.Name }
func (lib *sshCertIssuingCredentialLibrary) GetDescription() string         { return lib.Description }
func (lib *sshCertIssuingCredentialLibrary) GetVersion() uint32             { return lib.Version }
func (lib *sshCertIssuingCredentialLibrary) GetPurpose() credential.Purpose { return lib.Purpose }
func (lib *sshCertIssuingCredentialLibrary) GetCreateTime() *timestamp.Timestamp {
	return lib.CreateTime
}

func (lib *sshCertIssuingCredentialLibrary) GetUpdateTime() *timestamp.Timestamp {
	return lib.UpdateTime
}

func (lib *sshCertIssuingCredentialLibrary) CredentialType() globals.CredentialType {
	switch ct := lib.CredType; ct {
	case "":
		return globals.UnspecifiedCredentialType
	default:
		return globals.CredentialType(ct)
	}
}

// GetResourceType returns the resource type of the CredentialLibrary
func (lib *sshCertIssuingCredentialLibrary) GetResourceType() resource.Type {
	return resource.CredentialLibrary
}

func (lib *sshCertIssuingCredentialLibrary) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(genericIssuingCredentialLibrary).client"
	clientConfig := &clientConfig{
		Addr:          lib.VaultAddress,
		Token:         lib.Token,
		CaCert:        lib.CaCert,
		TlsServerName: lib.TlsServerName,
		TlsSkipVerify: lib.TlsSkipVerify,
		Namespace:     lib.Namespace,
	}

	if lib.ClientKey != nil {
		clientConfig.ClientCert = lib.ClientCert
		clientConfig.ClientKey = lib.ClientKey
	}

	client, err := vaultClientFactoryFn(ctx, clientConfig, WithWorkerFilter(lib.WorkerFilter))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

func generatePublicPrivateKeys(ctx context.Context, keyType string, keyBits int, opt ...credential.Option) (string, []byte, error) {
	const op = "vault.generatePublicPrivateKeys"
	pemBlock := pem.Block{}
	var sshKey ssh.PublicKey

	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return "", nil, errors.Wrap(ctx, err, op)
	}

	switch keyType {
	case KeyTypeRsa:
		pemBlock.Type = "RSA PRIVATE KEY" // these values are copied from the crypto ssh library in ssh/keys.go

		key, err := rsa.GenerateKey(opts.WithRandomReader, keyBits)
		if err != nil {
			return "", nil, errors.Wrap(ctx, err, op)
		}
		if sshKey, err = ssh.NewPublicKey(&key.PublicKey); err != nil {
			return "", nil, errors.Wrap(ctx, err, op)
		}

		pemBlock.Bytes = x509.MarshalPKCS1PrivateKey(key)

	case KeyTypeEd25519:
		pemBlock.Type = "OPENSSH PRIVATE KEY" // these values are copied from the crypto ssh library in ssh/keys.go

		pubKey, privKey, err := ed25519.GenerateKey(opts.WithRandomReader)
		if err != nil {
			return "", nil, errors.Wrap(ctx, err, op)
		}
		if sshKey, err = ssh.NewPublicKey(pubKey); err != nil {
			return "", nil, errors.Wrap(ctx, err, op)
		}

		if pemBlock.Bytes = edkey.MarshalED25519PrivateKey(privKey); pemBlock.Bytes == nil {
			return "", nil, errors.New(ctx, errors.Encode, op, "failed to marshal ed25519 private key")
		}

	case KeyTypeEcdsa:
		pemBlock.Type = "EC PRIVATE KEY" // these values are copied from the crypto ssh library in ssh/keys.go

		var curve elliptic.Curve
		switch keyBits {
		case 256:
			curve = elliptic.P256()
		case 384:
			curve = elliptic.P384()
		case 521:
			curve = elliptic.P521()
		default:
			return "", nil, errors.New(ctx, errors.InvalidParameter, op, "invalid KeyBits. when KeyType=ecdsa, KeyBits must be one of: 256, 384, or 521")
		}

		key, err := ecdsa.GenerateKey(curve, opts.WithRandomReader)
		if err != nil {
			return "", nil, errors.Wrap(ctx, err, op)
		}

		if sshKey, err = ssh.NewPublicKey(&key.PublicKey); err != nil {
			return "", nil, errors.Wrap(ctx, err, op)
		}

		if pemBlock.Bytes, err = x509.MarshalECPrivateKey(key); err != nil {
			return "", nil, errors.Wrap(ctx, err, op)
		}

	default:
		return "", nil, errors.New(ctx, errors.InvalidParameter, op, "invalid KeyType, must be one of: \"rsa\", \"ed25519\", or \"ecdsa\"")
	}

	publicKey := base64.StdEncoding.EncodeToString(sshKey.Marshal())
	privateKey := pem.EncodeToMemory(&pemBlock)
	if privateKey == nil {
		return "", nil, errors.New(ctx, errors.Encode, op, "failed to encode private key to PEM format")
	}
	return publicKey, privateKey, nil
}

type sshCertVaultBody struct {
	KeyType         string            `json:"key_type,omitempty"` // must be "rsa", "ed25519", or "ecdsa"
	KeyBits         int               `json:"key_bits,omitempty"` // with key_type=rsa, allowed values are: 2048 (default), 3072, or 4096; with key_type=ecdsa, allowed values are: 256 (default), 384, or 521; ignored with key_type=ed25519
	PublicKey       string            `json:"public_key,omitempty"`
	TTL             string            `json:"ttl,omitempty"`
	ValidPrincipals string            `json:"valid_principals,omitempty"` // this needs to be "generated" off of the username provided in config
	CertType        string            `json:"cert_type,omitempty"`        // this should always be "user"
	KeyId           string            `json:"key_id,omitempty"`           // this will be loaded directly from lib
	CriticalOptions map[string]string `json:"critical_options,omitempty"` // this will be loaded directly from lib
	Extensions      map[string]string `json:"extensions,omitempty"`       // this will be loaded directly from lib
}

var vaultPathRegexp = regexp.MustCompile(`^.+\/(sign|issue)\/[^\/\\\s]+$`)

// retrieveCredential retrieves a dynamic connection credential from Vault
// for a specific session and connection.
//
// Supported options: credential.WithTemplateData
func (lib *sshCertIssuingCredentialLibrary) retrieveCredential(ctx context.Context, op errors.Op, opt ...credential.Option) (dynamicCred, error) {
	opts, err := credential.GetOpts(opt...)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// Get the credential ID early. No need to get a secret from Vault
	// if there is no way to save it in the database.
	credId, err := newCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	client, err := lib.client(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// build as much of the payload as we can, since sign/issue share many attributes
	// Template the username
	tplate, err := template.New(ctx, lib.Username)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	username, err := tplate.Generate(ctx, opts.WithTemplateData)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	// Template the key ID if it's not empty
	keyId := lib.KeyId
	if keyId != "" {
		tplate, err = template.New(ctx, lib.KeyId)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		keyId, err = tplate.Generate(ctx, opts.WithTemplateData)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	var criticalOptions map[string]string
	if lib.CriticalOptions != nil {
		if json.Unmarshal(lib.CriticalOptions, &criticalOptions) != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	var extensions map[string]string
	if lib.Extensions != nil {
		if json.Unmarshal(lib.Extensions, &extensions) != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
	}

	validPrincipals := username
	if lib.AdditionalValidPrincipals != "" {
		validPrincipals = fmt.Sprintf("%s,%s", username, lib.AdditionalValidPrincipals)
	}

	payload := sshCertVaultBody{
		ValidPrincipals: validPrincipals,
		CertType:        "user",
		CriticalOptions: criticalOptions,
		Extensions:      extensions,
		TTL:             lib.Ttl,
		KeyId:           keyId,
	}

	var privateKey credential.PrivateKey
	var secret *vault.Secret

	match := vaultPathRegexp.FindStringSubmatch(lib.VaultPath)
	if len(match) < 2 {
		return nil, errors.New(ctx, errors.InvalidParameter, op, "vault path was not in an expected format. expected path containing \"sign\" or \"issue\"")
	}

	// by definition, if match exists, then match[1] == "sign" or "issue"
	switch match[1] {
	case "sign":
		payload.PublicKey, privateKey, err = generatePublicPrivateKeys(ctx, lib.KeyType, lib.KeyBits, credential.WithRandomReader(opts.WithRandomReader))
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		secret, err = client.post(ctx, lib.VaultPath, body)
		if err != nil {
			// TODO(mgaffney) 05/2021: detect if the error is because of an
			// expired or invalid token
			return nil, errors.Wrap(ctx, err, op)
		}
		if secret == nil {
			return nil, errors.E(ctx, errors.WithCode(errors.VaultEmptySecret), errors.WithOp(op))
		}

	case "issue":
		payload.KeyBits = lib.KeyBits
		if lib.KeyType == KeyTypeEcdsa {
			// this is a special case where internal to boundary, we refer to the crypto
			// library name, but vault refers to it simply as "ec" for "Elliptic Curve"
			payload.KeyType = "ec"
		} else {
			payload.KeyType = lib.KeyType
		}

		body, err := json.Marshal(payload)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}

		secret, err = client.post(ctx, lib.VaultPath, body)
		if err != nil {
			// TODO(mgaffney) 05/2021: detect if the error is because of an
			// expired or invalid token
			return nil, errors.Wrap(ctx, err, op)
		}
		if secret == nil {
			return nil, errors.E(ctx, errors.WithCode(errors.VaultEmptySecret), errors.WithOp(op))
		}

		pk, ok := secret.Data["private_key"].(string)
		if !ok {
			return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret did not contain a private key or response was not in the expected format")
		}

		privateKey = []byte(pk)
	}

	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second
	cred, err := newCredential(ctx, lib.GetPublicId(), secret.LeaseID, lib.TokenHmac, leaseDuration)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cred.PublicId = credId
	cred.IsRenewable = secret.Renewable // possibly set to just false

	// same location for both
	cert, ok := secret.Data["signed_key"].(string)
	if !ok {
		return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret did not contain a signed key or response was not in the expected format")
	}

	return &sshCertCred{
		sshPrivateKeyCred: &sshPrivateKeyCred{
			baseCred: &baseCred{
				Credential: cred,
				lib:        lib,
				secretData: secret.Data,
			},
			username:   username,
			privateKey: privateKey,
		},
		certificate: []byte(cert),
	}, nil
}

type ldapIssuingCredentialLibrary struct {
	PublicId                  string
	StoreId                   string
	Name                      string
	Description               string
	CreateTime                *timestamp.Timestamp
	UpdateTime                *timestamp.Timestamp
	Version                   uint32
	VaultPath                 string
	CredType                  string
	ProjectId                 string
	VaultAddress              string
	Namespace                 string
	CaCert                    []byte
	TlsServerName             string
	TlsSkipVerify             bool
	WorkerFilter              string
	Token                     TokenSecret
	CtToken                   []byte
	TokenHmac                 []byte
	TokenKeyId                string
	ClientCert                []byte
	ClientKey                 KeySecret
	CtClientKey               []byte
	ClientKeyId               string
	Username                  string
	KeyType                   string
	KeyBits                   int
	KeyId                     string
	Ttl                       string
	CriticalOptions           []byte
	Extensions                []byte
	Purpose                   credential.Purpose
	AdditionalValidPrincipals string
}

// GetPublicId returns the credential library's id.
func (lib *ldapIssuingCredentialLibrary) GetPublicId() string { return lib.PublicId }

// GetStoreId returns the credential library's credential store id.
func (lib *ldapIssuingCredentialLibrary) GetStoreId() string { return lib.StoreId }

// GetName returns the credential library's name.
func (lib *ldapIssuingCredentialLibrary) GetName() string { return lib.Name }

// GetDescription returns the credential library's description.
func (lib *ldapIssuingCredentialLibrary) GetDescription() string { return lib.Description }

// GetVersion returns the credential library's version.
func (lib *ldapIssuingCredentialLibrary) GetVersion() uint32 { return lib.Version }

// GetPurpose returns the credential library's purpose.
func (lib *ldapIssuingCredentialLibrary) GetPurpose() credential.Purpose { return lib.Purpose }

// GetCreateTime returns the credential library's create time.
func (lib *ldapIssuingCredentialLibrary) GetCreateTime() *timestamp.Timestamp { return lib.CreateTime }

// GetUpdateTime returns the credential library's update time.
func (lib *ldapIssuingCredentialLibrary) GetUpdateTime() *timestamp.Timestamp { return lib.UpdateTime }

// CredentialType returns the credential library's issuing credential type.
func (lib *ldapIssuingCredentialLibrary) CredentialType() globals.CredentialType {
	switch ct := lib.CredType; ct {
	case "":
		return globals.UnspecifiedCredentialType
	default:
		return globals.CredentialType(ct)
	}
}

// GetResourceType returns the credential library's resource type.
func (lib *ldapIssuingCredentialLibrary) GetResourceType() resource.Type {
	return resource.CredentialLibrary
}

// client produces a Vault API client using this credential library's data.
func (lib *ldapIssuingCredentialLibrary) client(ctx context.Context) (vaultClient, error) {
	const op = "vault.(genericIssuingCredentialLibrary).client"
	clientConfig := &clientConfig{
		Addr:          lib.VaultAddress,
		Token:         lib.Token,
		CaCert:        lib.CaCert,
		TlsServerName: lib.TlsServerName,
		TlsSkipVerify: lib.TlsSkipVerify,
		Namespace:     lib.Namespace,
	}

	if lib.ClientKey != nil {
		clientConfig.ClientCert = lib.ClientCert
		clientConfig.ClientKey = lib.ClientKey
	}

	client, err := vaultClientFactoryFn(ctx, clientConfig, WithWorkerFilter(lib.WorkerFilter))
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

var vaultLdapPathRegexp = regexp.MustCompile(`^.+\/(static-cred|creds).+$`)

// retrieveCredential retrieves a dynamic LDAP credential from Vault for a
// specific session and connection.
func (lib *ldapIssuingCredentialLibrary) retrieveCredential(ctx context.Context, op errors.Op, _ ...credential.Option) (dynamicCred, error) {
	credId, err := newCredentialId(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}

	client, err := lib.client(ctx)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	var secret *vault.Secret

	secret, err = client.get(ctx, lib.VaultPath)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	if secret == nil {
		return nil, errors.E(ctx, errors.WithCode(errors.VaultEmptySecret), errors.WithOp(op))
	}

	leaseDuration := time.Duration(secret.LeaseDuration) * time.Second
	cred, err := newCredential(ctx, lib.GetPublicId(), secret.LeaseID, lib.TokenHmac, leaseDuration)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op)
	}
	cred.PublicId = credId
	cred.IsRenewable = secret.Renewable

	upd := &usrPassDomainCred{
		baseCred: &baseCred{
			Credential: cred,
			lib:        lib,
			secretData: secret.Data,
		},
	}

	username, ok := secret.Data["username"].(string)
	if !ok {
		return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret did not contain a username or response was not in the expected format")
	}
	upd.username = username

	pwData, ok := secret.Data["password"].(string)
	if !ok {
		return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret did not contain a password or response was not in the expected format")
	}
	upd.password = credential.Password(pwData)

	matches := vaultLdapPathRegexp.FindStringSubmatch(lib.VaultPath)
	if len(matches) < 2 { // [0] is the vault path, [1] is static-cred or creds, if it exists.
		return nil, errors.New(ctx, errors.InvalidParameter, op, "vault path was not in an expected format. expected path containing \"static-cred\" or \"creds\"")
	}
	switch matches[1] {
	case "static-cred":
		dn, ok := secret.Data["dn"].(string)
		if !ok {
			return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret did not contain a dn or response was not in the expected format")
		}
		domain, err := extractDomainFromDn(dn)
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		upd.domain = domain
	case "creds":
		var dns []string
		dis, ok := secret.Data["distinguished_names"].([]any)
		if ok {
			for _, value := range dis {
				if v, ok := value.(string); ok {
					dns = append(dns, v)
				} else {
					return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret returned distinguished_names with non-string member")
				}
			}
		} else {
			return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret did not contain distinguished_names or response was not in the expected format")
		}
		if len(dns) == 0 {
			return nil, errors.New(ctx, errors.VaultInvalidCredentialMapping, op, "vault secret returned empty distinguished_names")
		}

		// In the Vault LDAP secrets engine, no deduplication occurs and order
		// is maintained from the LDIF statements, so the assumption here is
		// that the first DN should correspond to the user's creation in the
		// creation LDIF, which should correspond to the correct domain.
		// https://developer.hashicorp.com/vault/docs/secrets/ldap#dynamic-credentials
		domain, err := extractDomainFromDn(dns[0])
		if err != nil {
			return nil, errors.Wrap(ctx, err, op)
		}
		upd.domain = domain
	}

	return upd, nil
}

// extractDomainFromDn composes a domain name from all the "dc" attributes in an
// LDAP DN.
func extractDomainFromDn(dnStr string) (string, error) {
	if dnStr == "" {
		return "", fmt.Errorf("empty DN")
	}

	dn, err := ldapv3.ParseDN(dnStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse DN: %w", err)
	}

	var dcs []string
	for _, rdn := range dn.RDNs {
		for _, attr := range rdn.Attributes {
			// "0.9.2342.19200300.100.1.25" is the OID for the "dc" attribute
			// and it is a valid representation in a DN string.
			// (https://docs.ldap.com/specs/rfc4519.txt)
			if strings.EqualFold(attr.Type, "dc") || strings.EqualFold(attr.Type, "0.9.2342.19200300.100.1.25") {
				dcs = append(dcs, attr.Value)
			}
		}
	}
	if len(dcs) == 0 {
		return "", fmt.Errorf("no domain component (dc) attribute found in dn")
	}

	return strings.Join(dcs, "."), nil
}
