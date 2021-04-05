package vault

import (
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	"google.golang.org/protobuf/proto"
)

// A Lease contains a vault lease. It is owned by a credential library.
type Lease struct {
	*store.Lease
	tableName  string        `gorm:"-"`
	expiration time.Duration `gorm:"-"`
}

func newLease(libraryId, sessionId, leaseId string, tokenSha256 []byte, expiration time.Duration) (*Lease, error) {
	const op = "vault.newLease"
	if libraryId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no library id")
	}
	if sessionId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no session id")
	}
	if leaseId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no lease id")
	}
	if len(tokenSha256) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no tokenSha256")
	}
	if expiration == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no expiration")
	}

	l := &Lease{
		expiration: expiration.Round(time.Second),
		Lease: &store.Lease{
			LibraryId:   libraryId,
			SessionId:   sessionId,
			LeaseId:     leaseId,
			TokenSha256: tokenSha256,
		},
	}
	return l, nil
}

func allocLease() *Lease {
	return &Lease{
		Lease: &store.Lease{},
	}
}

func (l *Lease) clone() *Lease {
	cp := proto.Clone(l.Lease)
	return &Lease{
		expiration: l.expiration,
		Lease:      cp.(*store.Lease),
	}
}

// TableName returns the table name.
func (l *Lease) TableName() string {
	if l.tableName != "" {
		return l.tableName
	}
	return "credential_vault_lease"
}

// SetTableName sets the table name.
func (l *Lease) SetTableName(n string) {
	l.tableName = n
}

func (l *Lease) oplog(op oplog.OpType) oplog.Metadata {
	metadata := oplog.Metadata{
		"resource-public-id": []string{l.PublicId},
		"resource-type":      []string{"credential-vault-lease"},
		"op-type":            []string{op.String()},
	}
	if l.LibraryId != "" {
		metadata["library-id"] = []string{l.LibraryId}
	}
	return metadata
}

func (l *Lease) insertQuery() (query string, queryValues []interface{}) {
	query = insertLeaseQuery

	exp := int(l.expiration.Round(time.Second).Seconds())
	queryValues = []interface{}{
		l.PublicId,
		l.LibraryId,
		l.SessionId,
		l.TokenSha256,
		l.LeaseId,
		l.IsRenewable,
		"now()",
		exp,
	}
	return
}
