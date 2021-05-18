package vault

import (
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

const externalIdSentinel = "\ufffenone"

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
	if len(tokenHmac) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no tokenHmac")
	}

	if externalId == "" {
		externalId = externalIdSentinel
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

func (c *Credential) clone() *Credential {
	cp := proto.Clone(c.Credential)
	return &Credential{
		expiration: c.expiration,
		Credential: cp.(*store.Credential),
	}
}

// TableName returns the table name.
func (c *Credential) TableName() string {
	if c.tableName != "" {
		return c.tableName
	}
	return "credential_vault_credential"
}

// SetTableName sets the table name.
func (c *Credential) SetTableName(n string) {
	c.tableName = n
}

func (c *Credential) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{c.PublicId},
		"resource-type":      []string{"credential-vault-credential"},
		"op-type":            []string{op.String()},
	}
	if c.LibraryId != "" {
		metadata["library-id"] = []string{c.LibraryId}
	}
	return metadata
}

func (c *Credential) insertQuery() (query string, queryValues []interface{}) {
	query = insertCredentialQuery

	exp := int(c.expiration.Round(time.Second).Seconds())
	queryValues = []interface{}{
		c.PublicId,
		c.LibraryId,
		c.SessionId,
		c.TokenHmac,
		c.ExternalId,
		c.IsRenewable,
		"now()",
		exp,
	}
	return
}
