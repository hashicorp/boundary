package vault

import (
	"database/sql"
	"time"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db/sanitize"
	"github.com/hashicorp/boundary/internal/db/sentinel"
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
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no library id")
	}
	if sessionId == "" {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no session id")
	}
	if len(tokenHmac) == 0 {
		return nil, errors.NewDeprecated(errors.InvalidParameter, op, "no tokenHmac")
	}

	status := string(ActiveCredential)
	externalId = sanitize.String(externalId)
	if externalId == "" {
		externalId = sentinel.ExternalIdNone
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
		sql.Named("public_id", c.PublicId),
		sql.Named("library_id", c.LibraryId),
		sql.Named("session_id", c.SessionId),
		sql.Named("token_hmac", c.TokenHmac),
		sql.Named("external_id", c.ExternalId),
		sql.Named("is_renewable", c.IsRenewable),
		sql.Named("status", c.Status),
		sql.Named("last_renewal_time", "now()"),
	}
	switch {
	case c.expiration == 0:
		query = insertCredentialWithInfiniteExpirationQuery
	default:
		query = insertCredentialWithExpirationQuery
		queryValues = append(queryValues, sql.Named("expiration_time", int(c.expiration.Round(time.Second).Seconds())))
	}
	return
}

func (c *Credential) updateSessionQuery(purpose credential.Purpose) (query string, queryValues []interface{}) {
	queryValues = []interface{}{
		sql.Named("public_id", c.PublicId),
		sql.Named("library_id", c.LibraryId),
		sql.Named("session_id", c.SessionId),
		sql.Named("purpose", string(purpose)),
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
