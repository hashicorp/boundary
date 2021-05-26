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

var _ credential.Dynamic = (*privateCredential)(nil)

type privateCredential struct {
	id         string
	sessionId  string
	lib        *privateLibrary
	secretData map[string]interface{}
	purpose    credential.Purpose
}

func (pc *privateCredential) GetPublicId() string           { return pc.id }
func (pc *privateCredential) GetSessionId() string          { return pc.sessionId }
func (pc *privateCredential) Secret() credential.SecretData { return pc.secretData }
func (pc *privateCredential) Library() credential.Library   { return pc.lib }
func (pc *privateCredential) Purpose() credential.Purpose   { return pc.purpose }

var _ credential.Library = (*privateLibrary)(nil)

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

func (pl *privateLibrary) GetPublicId() string                 { return pl.PublicId }
func (pl *privateLibrary) GetStoreId() string                  { return pl.StoreId }
func (pl *privateLibrary) GetName() string                     { return pl.Name }
func (pl *privateLibrary) GetDescription() string              { return pl.Description }
func (pl *privateLibrary) GetVersion() uint32                  { return pl.Version }
func (pl *privateLibrary) GetCreateTime() *timestamp.Timestamp { return pl.CreateTime }
func (pl *privateLibrary) GetUpdateTime() *timestamp.Timestamp { return pl.UpdateTime }

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

type privPurpLibrary struct {
	*privateLibrary
	credential.Purpose
}

func allocPrivPurpLibrary() *privPurpLibrary {
	return &privPurpLibrary{
		privateLibrary: &privateLibrary{},
	}
}

type requestMap struct {
	ids map[string][]credential.Purpose
	err error
}

func newMapper(requests []credential.RequestDynamic) *requestMap {
	ids := make(map[string][]credential.Purpose, len(requests))
	for _, req := range requests {
		if purps, ok := ids[req.LibraryId]; ok {
			for _, purp := range purps {
				if purp == req.Purpose {
					return &requestMap{
						err: errors.E(errors.WithCode(errors.InvalidParameter), errors.WithMsg("duplicate library and purpose")),
					}
				}
			}
		}
		ids[req.LibraryId] = append(ids[req.LibraryId], req.Purpose)
	}
	return &requestMap{
		ids: ids,
	}
}

func (m *requestMap) Err() error {
	return m.err
}

func (m *requestMap) LibIds() []string {
	if m.err != nil {
		return nil
	}
	var ids []string
	for id := range m.ids {
		ids = append(ids, id)
	}
	return ids
}

func (m *requestMap) Map(libs []*privateLibrary) []*privPurpLibrary {
	if m.err != nil {
		return nil
	}
	var ppls []*privPurpLibrary
	for _, lib := range libs {
		purps, ok := m.ids[lib.GetPublicId()]
		if !ok {
			m.err = errors.E(errors.WithCode(errors.InvalidParameter), errors.WithMsg("unknown library"))
			return nil
		}
		for _, purp := range purps {
			ppl := allocPrivPurpLibrary()
			ppl.privateLibrary = lib
			ppl.Purpose = purp
			ppls = append(ppls, ppl)
		}
	}
	return ppls
}
