package authtoken

import (
	"context"
	"fmt"
	mathrand "math/rand"
	"time"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/gen/controller/tokens"
	"github.com/hashicorp/boundary/internal/kms"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/mr-tron/base58"
	"google.golang.org/protobuf/proto"
)

// writableAuthToken is used for auth token writes.  Since gorm relies on the TableName interface this allows
// us to use a base table for writes and a view for reads.
type writableAuthToken struct {
	*store.AuthToken
	tableName string `gorm:"-"`
}

func (s *writableAuthToken) clone() *writableAuthToken {
	cp := proto.Clone(s.AuthToken)
	return &writableAuthToken{
		AuthToken: cp.(*store.AuthToken),
	}
}

func (s *writableAuthToken) toAuthToken() *AuthToken {
	cp := proto.Clone(s.AuthToken)
	return &AuthToken{
		AuthToken: cp.(*store.AuthToken),
	}
}

// A AuthToken contains auth tokens. It is owned by a scope.
type AuthToken struct {
	*store.AuthToken
	tableName string `gorm:"-"`
}

func (s *AuthToken) clone() *AuthToken {
	cp := proto.Clone(s.AuthToken)
	return &AuthToken{
		AuthToken: cp.(*store.AuthToken),
	}
}

func (s *AuthToken) toWritableAuthToken() *writableAuthToken {
	cp := proto.Clone(s.AuthToken)
	return &writableAuthToken{
		AuthToken: cp.(*store.AuthToken),
	}
}

// encrypt the entry's data using the provided cipher (wrapping.Wrapper)
func (s *writableAuthToken) encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "authtoken.(Repository).encrypt"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, cipher, s.AuthToken, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Encrypt))
	}
	s.KeyId = cipher.KeyID()
	return nil
}

// decrypt will decrypt the auth token's value using the provided cipher (wrapping.Wrapper)
func (s *AuthToken) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	const op = "authtoken.(Repository).decrypt"
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, s.AuthToken, nil); err != nil {
		return errors.Wrap(err, op, errors.WithCode(errors.Decrypt))
	}
	return nil
}

const (
	AuthTokenPrefix = "at"
	// The version prefix is used to differentiate token versions just for future proofing.
	TokenValueVersionPrefix = "0"
	tokenLength             = 24
)

func newAuthTokenId() (string, error) {
	const op = "authtoken.newAuthTokenId"
	id, err := db.NewPublicId(AuthTokenPrefix)
	if err != nil {
		return "", errors.Wrap(err, op)
	}
	return id, nil
}

// newAuthToken generates a token with a version prefix.
func newAuthToken() (string, error) {
	const op = "authtoken.newAuthToken"
	token, err := base62.Random(tokenLength)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithCode(errors.Io))
	}
	return fmt.Sprintf("%s%s", TokenValueVersionPrefix, token), nil
}

// EncryptToken is a shared function for encrypting a token value for return to
// the user.
func EncryptToken(ctx context.Context, kmsCache *kms.Kms, scopeId, publicId, token string) (string, error) {
	const op = "authtoken.EncryptToken"
	r := mathrand.New(mathrand.NewSource(time.Now().UnixNano()))

	s1Info := &tokens.S1TokenInfo{
		Token:      token,
		Confounder: make([]byte, r.Intn(30)),
	}
	r.Read(s1Info.Confounder)

	marshaledS1Info, err := proto.Marshal(s1Info)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithCode(errors.Encode))
	}

	tokenWrapper, err := kmsCache.GetWrapper(ctx, scopeId, kms.KeyPurposeTokens)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithMsg("unable to get wrapper"))
	}

	blobInfo, err := tokenWrapper.Encrypt(ctx, []byte(marshaledS1Info), []byte(publicId))
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithCode(errors.Encrypt))
	}

	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", errors.Wrap(err, op, errors.WithCode(errors.Encode))
	}

	encoded := base58.FastBase58Encoding(marshaledBlob)

	return globals.ServiceTokenV1 + encoded, nil
}
