package vault

import (
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A Credential contains the data for a Vault lease. It is owned by a credential library.
type Credential struct {
	*store.Credential
	tableName  string        `gorm:"-"`
	expiration time.Duration `gorm:"-"`
}

func newCredential(libraryId, sessionId, externalId string, tokenHmac []byte, expiration time.Duration) (*Credential, error) {
	const op = "vault.newCredential"
	if libraryId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no library id")
	}
	if sessionId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no session id")
	}
	if externalId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no external id")
	}
	if len(tokenHmac) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no tokenHmac")
	}
	if expiration == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no expiration")
	}

	l := &Credential{
		expiration: expiration.Round(time.Second),
		Credential: &store.Credential{
			LibraryId:  libraryId,
			SessionId:  sessionId,
			ExternalId: externalId,
			TokenHmac:  tokenHmac,
		},
	}
	return l, nil
}

func allocCredential() *Credential {
	return &Credential{
		Credential: &store.Credential{},
	}
}

func (l *Credential) clone() *Credential {
	cp := proto.Clone(l.Credential)
	return &Credential{
		expiration: l.expiration,
		Credential: cp.(*store.Credential),
	}
}

// TableName returns the table name.
func (l *Credential) TableName() string {
	if l.tableName != "" {
		return l.tableName
	}
	return "credential_vault_credential"
}

// SetTableName sets the table name.
func (l *Credential) SetTableName(n string) {
	l.tableName = n
}

func (l *Credential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{l.PublicId},
		"resource-type":      []string{"credential-vault-credential"},
		"op-type":            []string{op.String()},
	}
	if l.LibraryId != "" {
		metadata["library-id"] = []string{l.LibraryId}
	}
	return metadata
}

func (l *Credential) insertQuery() (query string, queryValues []interface{}) {
	query = insertCredentialQuery

	exp := int(l.expiration.Round(time.Second).Seconds())
	queryValues = []interface{}{
		l.PublicId,
		l.LibraryId,
		l.SessionId,
		l.TokenHmac,
		l.ExternalId,
		l.IsRenewable,
		"now()",
		exp,
	}
	return
}
