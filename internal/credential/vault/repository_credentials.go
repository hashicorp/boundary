package vault

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
)

// IssueCredentials issues and returns dynamic credentials for sessionId. A
// dynamic credential is retrieved from Vault for each libraryId. The
// number of credentials returned is equal to the number of libraryIds. If
// a credential cannot be retrieved for the one of the libraryIds, and
// error is returned with no credentials.
func (r *Repository) IssueCredentials(ctx context.Context, sessionId string, libraryIds []string, _ ...Option) ([]credential.Dynamic, error) {
	panic("not implemented")
}

type privateLibrary struct {
	PublicId    string `gorm:"primary_key"`
	StoreId     string
	Name        string
	Description string
	CreateTime  *timestamp.Timestamp
	UpdateTime  *timestamp.Timestamp
	Version     uint32

	ScopeId         string
	VaultPath       string
	HttpMethod      string
	HttpRequestBody []byte

	VaultAddress  string
	Namespace     string
	CaCert        []byte
	TlsServerName string
	TlsSkipVerify bool

	TokenHmac  []byte
	Token      []byte
	CtToken    []byte
	TokenKeyId string

	ClientCert  []byte
	ClientKey   []byte
	CtClientKey []byte
	ClientKeyId string
}

var _ credential.Library = (*privateLibrary)(nil)

func (pl *privateLibrary) GetVersion() uint32                  { return pl.Version }
func (pl *privateLibrary) GetCreateTime() *timestamp.Timestamp { return pl.CreateTime }
func (pl *privateLibrary) GetUpdateTime() *timestamp.Timestamp { return pl.UpdateTime }
func (pl *privateLibrary) GetName() string                     { return pl.Name }
func (pl *privateLibrary) GetDescription() string              { return pl.Description }
func (pl *privateLibrary) GetStoreId() string                  { return pl.StoreId }

func allocPrivateLibrary() *privateLibrary {
	return &privateLibrary{}
}

func (pl *privateLibrary) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(privateLibrary).decrypt"

	if pl.CtToken != nil {
		type ptk struct {
			Token   []byte `wrapping:"pt,token_data"`
			CtToken []byte `wrapping:"ct,token_data"`
		}
		ptkv := &ptk{
			CtToken: pl.CtToken,
		}
		if err := structwrapping.UnwrapStruct(ctx, cipher, ptkv, nil); err != nil {
			return errors.Wrap(err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("token"))
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
			return errors.Wrap(err, op, errors.WithCode(errors.Decrypt), errors.WithMsg("client certificate"))
		}
		pl.ClientKey = pckv.Key
	}
	return nil
}

func (pl *privateLibrary) client() (*client, error) {
	const op = "vault.(privateLibrary).client"
	clientConfig := &clientConfig{
		Addr:          pl.VaultAddress,
		Token:         string(pl.Token),
		CaCert:        pl.CaCert,
		TlsServerName: pl.TlsServerName,
		TlsSkipVerify: pl.TlsSkipVerify,
		Namespace:     pl.Namespace,
	}

	if pl.ClientKey != nil {
		clientConfig.ClientCert = pl.ClientCert
		clientConfig.ClientKey = pl.ClientKey
	}

	client, err := newClient(clientConfig)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

// GetPublicId returns the public id.
func (pl *privateLibrary) GetPublicId() string { return pl.PublicId }

// TableName returns the table name for gorm.
func (pl *privateLibrary) TableName() string {
	return "credential_vault_library_private"
}

func (r *Repository) getPrivateLibraries(ctx context.Context, libIds []string) ([]*privateLibrary, error) {
	const op = "vault.(Repository).getPrivateLibraries"
	if len(libIds) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no library ids")
	}

	inClause := strings.TrimSuffix(strings.Repeat("?,", len(libIds)), ",")

	query := fmt.Sprintf(selectPrivateLibrariesQuery, inClause)

	var params []interface{}
	for _, v := range libIds {
		params = append(params, v)
	}
	rows, err := r.reader.Query(ctx, query, params)
	if err != nil {
		return nil, errors.Wrap(err, op, errors.WithMsg("query failed"))
	}
	defer rows.Close()

	var libs []*privateLibrary
	for rows.Next() {
		var lib privateLibrary
		if err := r.reader.ScanRows(rows, &lib); err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("scan row failed"))
		}
		libs = append(libs, &lib)
	}

	for _, pl := range libs {
		databaseWrapper, err := r.kms.GetWrapper(ctx, pl.ScopeId, kms.KeyPurposeDatabase)
		if err != nil {
			return nil, errors.Wrap(err, op, errors.WithMsg("unable to get database wrapper"))
		}

		if err := pl.decrypt(ctx, databaseWrapper); err != nil {
			return nil, errors.Wrap(err, op)
		}
	}

	return libs, nil
}
