package vault

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/db/timestamp"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"google.golang.org/protobuf/proto"
)

var _ credential.Dynamic = (*actualCredential)(nil)

type actualCredential struct {
	id         string
	sessionId  string
	lib        *privateLibrary
	secretData map[string]interface{}
	purpose    credential.Purpose
}

func (ac *actualCredential) GetPublicId() string           { return ac.id }
func (ac *actualCredential) GetSessionId() string          { return ac.sessionId }
func (ac *actualCredential) Secret() credential.SecretData { return ac.secretData }
func (ac *actualCredential) Library() credential.Library   { return ac.lib }
func (ac *actualCredential) Purpose() credential.Purpose   { return ac.purpose }

var _ credential.Library = (*privateLibrary)(nil)

type privateLibrary struct {
	PublicId        string `gorm:"primary_key"`
	StoreId         string
	Name            string
	Description     string
	CreateTime      *timestamp.Timestamp
	UpdateTime      *timestamp.Timestamp
	Version         uint32
	ScopeId         string
	VaultPath       string
	HttpMethod      string
	HttpRequestBody []byte
	VaultAddress    string
	Namespace       string
	CaCert          []byte
	TlsServerName   string
	TlsSkipVerify   bool
	TokenHmac       []byte
	Token           TokenSecret
	CtToken         []byte
	TokenKeyId      string
	ClientCert      []byte
	ClientKey       KeySecret
	CtClientKey     []byte
	ClientKeyId     string
	Purpose         credential.Purpose `gorm:"-"`
}

func (pl *privateLibrary) clone() *privateLibrary {
	// The 'append(a[:0:0], a...)' comes from
	// https://github.com/go101/go101/wiki/How-to-perfectly-clone-a-slice%3F
	return &privateLibrary{
		PublicId:        pl.PublicId,
		StoreId:         pl.StoreId,
		Name:            pl.Name,
		Description:     pl.Description,
		CreateTime:      proto.Clone(pl.CreateTime).(*timestamp.Timestamp),
		UpdateTime:      proto.Clone(pl.UpdateTime).(*timestamp.Timestamp),
		Version:         pl.Version,
		ScopeId:         pl.ScopeId,
		VaultPath:       pl.VaultPath,
		HttpMethod:      pl.HttpMethod,
		HttpRequestBody: append(pl.HttpRequestBody[:0:0], pl.HttpRequestBody...),
		VaultAddress:    pl.VaultAddress,
		Namespace:       pl.Namespace,
		CaCert:          append(pl.CaCert[:0:0], pl.CaCert...),
		TlsServerName:   pl.TlsServerName,
		TlsSkipVerify:   pl.TlsSkipVerify,
		TokenHmac:       append(pl.TokenHmac[:0:0], pl.TokenHmac...),
		Token:           append(pl.Token[:0:0], pl.Token...),
		CtToken:         append(pl.CtToken[:0:0], pl.CtToken...),
		TokenKeyId:      pl.TokenKeyId,
		ClientCert:      append(pl.ClientCert[:0:0], pl.ClientCert...),
		ClientKey:       append(pl.ClientKey[:0:0], pl.ClientKey...),
		CtClientKey:     append(pl.CtClientKey[:0:0], pl.CtClientKey...),
		ClientKeyId:     pl.ClientKeyId,
		Purpose:         pl.Purpose,
	}
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

func (pl *privateLibrary) client() (*client, error) {
	const op = "vault.(privateLibrary).client"
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

	client, err := newClient(clientConfig)
	if err != nil {
		return nil, errors.WrapDeprecated(err, op, errors.WithMsg("unable to create vault client"))
	}
	return client, nil
}

// TableName returns the table name for gorm.
func (pl *privateLibrary) TableName() string {
	return "credential_vault_library_private"
}

func (r *Repository) getPrivateLibraries(ctx context.Context, requests []credential.Request) ([]*privateLibrary, error) {
	const op = "vault.(Repository).getPrivateLibraries"

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

	query := fmt.Sprintf(selectPrivateLibrariesQuery, inClause)

	var params []interface{}
	for idx, v := range libIds {
		params = append(params, sql.Named(fmt.Sprintf("%d", idx+1), v))
	}
	rows, err := r.reader.Query(ctx, query, params)
	if err != nil {
		return nil, errors.Wrap(ctx, err, op, errors.WithMsg("query failed"))
	}
	defer rows.Close()

	var libs []*privateLibrary
	for rows.Next() {
		var lib privateLibrary
		if err := r.reader.ScanRows(rows, &lib); err != nil {
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
		databaseWrapper, err := r.kms.GetWrapper(ctx, pl.ScopeId, kms.KeyPurposeDatabase)
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
