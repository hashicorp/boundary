package authtoken

import (
	"context"
	"fmt"

	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-kms-wrapping/structwrapping"
	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/authtoken/store"
	"github.com/hashicorp/watchtower/internal/db"
	"google.golang.org/protobuf/proto"
)

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

// Encrypt the entry's data using the provided cipher (wrapping.Wrapper)
func (s *AuthToken) Encrypt(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, cipher, s.AuthToken, nil); err != nil {
		return fmt.Errorf("error encrypting auth token: %w", err)
	}
	return nil
}

// Decrypt will decrypt the auth token's value using the provided cipher (wrapping.Wrapper)
func (s *AuthToken) Decrypt(ctx context.Context, cipher wrapping.Wrapper) error {
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
		return "", fmt.Errorf("Unable to generate auth token: %w", err)
	}
	return fmt.Sprintf("%s%s", TokenValueVersionPrefix, token), nil
}
