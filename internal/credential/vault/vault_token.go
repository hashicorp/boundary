package vault

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"time"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/oplog"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"golang.org/x/crypto/blake2b"
	"google.golang.org/protobuf/proto"
)

// A TokenStatus represents the status of a vault token.
type TokenStatus string

const (
	// CurrentToken represents a vault token for a credential store that is
	// used for retrieving credentials. Tokens in this state are renewed
	// before they expire. A credential store can have only one current
	// token.
	CurrentToken TokenStatus = "current"

	// MaintainingToken represents a vault token that is no longer being
	// used for retrieving credentials but is being renewed because it was
	// used to retrieve credentials which are still being used in a
	// session. After the dependent sessions are terminated, the token is
	// revoked in Vault and the status transitions to RevokedToken. but is
	// no longer being used for retrieving credentials.
	MaintainingToken TokenStatus = "maintaining"

	// RevokeToken represents a token that should be revoked.
	RevokeToken TokenStatus = "revoke"

	// RevokedToken represents a token that has been revoked. This is a
	// terminal status. It does not transition to ExpiredToken.
	RevokedToken TokenStatus = "revoked"

	// ExpiredToken represents a token that expired. This is a terminal
	// status. It does not transition to RevokedToken.
	ExpiredToken TokenStatus = "expired"
)

// Token contains a vault token. It is owned by a credential store.
type Token struct {
	*store.Token
	tableName  string        `gorm:"-"`
	expiration time.Duration `gorm:"-"`
}

func newToken(storeId string, token TokenSecret, accessor []byte, expiration time.Duration) (*Token, error) {
	const op = "vault.newToken"
	if storeId == "" {
		return nil, errors.New(errors.InvalidParameter, op, "no store id")
	}
	if len(token) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no vault token")
	}
	if len(accessor) == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no vault token accessor")
	}
	if expiration == 0 {
		return nil, errors.New(errors.InvalidParameter, op, "no expiration")
	}

	tokenCopy := make(TokenSecret, len(token))
	copy(tokenCopy, token)
	accessorCopy := make([]byte, len(accessor))
	copy(accessorCopy, accessor)

	key := blake2b.Sum256(accessorCopy)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(tokenCopy)
	hmac := mac.Sum(nil)

	t := &Token{
		expiration: expiration.Round(time.Second),
		Token: &store.Token{
			StoreId:   storeId,
			TokenHmac: hmac,
			Token:     tokenCopy,
			Status:    string(CurrentToken),
		},
	}
	return t, nil
}

func allocToken() *Token {
	return &Token{
		Token: &store.Token{},
	}
}

func (t *Token) clone() *Token {
	cp := proto.Clone(t.Token)
	return &Token{
		expiration: t.expiration,
		Token:      cp.(*store.Token),
	}
}

// TableName returns the table name.
func (t *Token) TableName() string {
	if t.tableName != "" {
		return t.tableName
	}
	return "credential_vault_token"
}

// SetTableName sets the table name.
func (t *Token) SetTableName(n string) {
	t.tableName = n
}

func (t *Token) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(Token).encrypt"
	if err := structwrapping.WrapStruct(ctx, cipher, t.Token, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Encrypt))
	}
	t.KeyId = cipher.KeyID()
	return nil
}

func (t *Token) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "vault.(Token).decrypt"
	if err := structwrapping.UnwrapStruct(ctx, cipher, t.Token, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

func (t *Token) insertQuery() (query string, queryValues []interface{}) {
	query = insertTokenQuery

	exp := int(t.expiration.Round(time.Second).Seconds())
	queryValues = []interface{}{
		t.TokenHmac,
		t.CtToken,
		t.StoreId,
		t.KeyId,
		t.Status,
		"now()",
		exp,
	}
	return
}

func (t *Token) updateStatusQuery(status TokenStatus) (query string, queryValues []interface{}) {
	query = updateTokenStatusQuery

	queryValues = []interface{}{
		status,
		t.TokenHmac,
	}
	return
}

func (t *Token) updateExpirationQuery() (query string, queryValues []interface{}) {
	query = updateTokenExpirationQuery

	exp := int(t.expiration.Round(time.Second).Seconds())
	queryValues = []interface{}{
		exp,
		t.TokenHmac,
	}
	return
}

func (t *Token) oplogMessage(opType db.OpType) *oplog.Message {
	msg := oplog.Message{
		Message:  t.clone(),
		TypeName: t.TableName(),
	}
	switch opType {
	case db.CreateOp:
		msg.OpType = oplog.OpType_OP_TYPE_CREATE
	case db.UpdateOp:
		msg.OpType = oplog.OpType_OP_TYPE_UPDATE
		// msg.FieldMaskPaths = opts.WithFieldMaskPaths
		// msg.SetToNullPaths = opts.WithNullPaths
	case db.DeleteOp:
		msg.OpType = oplog.OpType_OP_TYPE_DELETE
	}
	return &msg
}

func (t *Token) renewalIn() time.Duration {
	// Token renewal should be attempted half way to expiration
	return t.expiration / 2
}
