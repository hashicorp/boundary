package authtoken

import (
	"context"
	"fmt"

	"github.com/btcsuite/btcutil/base58"
	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/types/scope"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"github.com/hashicorp/vault/sdk/helper/base62"
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
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, cipher, s.AuthToken, nil); err != nil {
		return fmt.Errorf("error encrypting auth token: %w", err)
	}
	s.KeyId = cipher.KeyID()
	return nil
}

// decrypt will decrypt the auth token's value using the provided cipher (wrapping.Wrapper)
func (s *AuthToken) decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.UnwrapStruct(ctx, cipher, s.AuthToken, nil); err != nil {
		return fmt.Errorf("error decrypting auth token: %w", err)
	}
	return nil
}

const (
	AuthTokenPrefix = "t"
	// The version prefix is used to differentiate token versions just for future proofing.
	TokenValueVersionPrefix = "0"
	tokenLength             = 24
)

func newAuthTokenId() (string, error) {
	id, err := db.NewPublicId(AuthTokenPrefix)
	if err != nil {
		return "", fmt.Errorf("new auth token id: %w", err)
	}
	return id, err
}

// newAuthToken generates a token with a version prefix.
func newAuthToken() (string, error) {
	token, err := base62.Random(tokenLength)
	if err != nil {
		return "", fmt.Errorf("unable to generate auth token: %w", err)
	}
	return fmt.Sprintf("%s%s", TokenValueVersionPrefix, token), nil
}

// EncryptToken is a shared function for encrypting a token value for return to
// the user. We always use the global scope because on authenticate we don't
// have scope info at this point and the idea is to remove a DB lookup if the
// token is made up/invalid so as to prevent DDoS against a third party service
// by just randomly guessing tokens.
func EncryptToken(ctx context.Context, kmsCache *kms.Kms, publicId, token string) (string, error) {
	tokenWrapper, err := kmsCache.GetWrapper(ctx, scope.Global.String(), kms.KeyPurposeTokens)
	if err != nil {
		return "", fmt.Errorf("unable to get wrapper: %w", err)
	}

	blobInfo, err := tokenWrapper.Encrypt(ctx, []byte(token), []byte(publicId))
	if err != nil {
		return "", fmt.Errorf("error encrypting token: %w", err)
	}

	marshaledBlob, err := proto.Marshal(blobInfo)
	if err != nil {
		return "", fmt.Errorf("error marshaling encrypted token: %w", err)
	}

	return globals.ServiceTokenV1 + base58.Encode(marshaledBlob), nil
}
