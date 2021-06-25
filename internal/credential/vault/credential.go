package vault

import (
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A CredentialStatus represents the status of a vault credential.
type CredentialStatus string

const (
	// ActiveCredential represents a vault credential that is being used in
	// an active session. Credentials in this state are renewed before they
	// expire.
	ActiveCredential CredentialStatus = "active"

	// RevokeCredential represents a vault credential that needs to be
	// revoked.
	RevokeCredential CredentialStatus = "revoke"

	// RevokedCredential represents a credential that has been revoked. This is a
	// terminal status. It does not transition to ExpiredCredential.
	RevokedCredential CredentialStatus = "revoked"

	// ExpiredCredential represents a credential that expired. This is a terminal
	// status. It does not transition to RevokedCredential.
	ExpiredCredential CredentialStatus = "expired"
)

const (
	externalIdSentinel = "\ufffenone"

	// UnknownCredentialStatus represents a credential that has an unknown
	// status.
	UnknownCredentialStatus CredentialStatus = "unknown"
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
	if len(tokenHmac) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no tokenHmac")
	}

	status := string(ActiveCredential)
	if externalId == "" {
		externalId = externalIdSentinel
		status = string(UnknownCredentialStatus)
	}

	l := &Credential{
		expiration: expiration.Round(time.Second),
		Credential: &store.Credential{
			LibraryId:  libraryId,
			SessionId:  sessionId,
			ExternalId: externalId,
			TokenHmac:  tokenHmac,
			Status:     status,
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
	queryValues = []interface{}{
		c.PublicId,
		c.LibraryId,
		c.SessionId,
		c.TokenHmac,
		c.ExternalId,
		c.IsRenewable,
		c.Status,
		"now()",
	}
	switch {
	case c.expiration == 0:
		query = insertCredentialWithInfiniteExpirationQuery
	default:
		query = insertCredentialWithExpirationQuery
		queryValues = append(queryValues, int(c.expiration.Round(time.Second).Seconds()))
	}
	return
}

func (c *Credential) updateSessionQuery(purpose credential.Purpose) (query string, queryValues []interface{}) {
	queryValues = []interface{}{
		c.PublicId,
		c.LibraryId,
		c.SessionId,
		string(purpose),
	}
	query = updateSessionCredentialQuery
	return
}

func (c *Credential) updateExpirationQuery() (query string, queryValues []interface{}) {
	queryValues = []interface{}{
		int(c.expiration.Round(time.Second).Seconds()),
		c.PublicId,
	}
	query = updateCredentialExpirationQuery
	return
}

func (c *Credential) updateStatusQuery(status CredentialStatus) (query string, queryValues []interface{}) {
	queryValues = []interface{}{
		status,
		c.PublicId,
	}
	query = updateCredentialStatusQuery
	return
}
