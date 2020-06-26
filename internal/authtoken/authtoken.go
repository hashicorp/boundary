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

// NewAuthToken creates a new in memory AuthToken assigned to scopeId for the user id and authmethod used.
// All options are ignored.
func NewAuthToken(scopeId, userId, authMethodId string, opt ...Option) (*AuthToken, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new: auth token: no scope id: %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return nil, fmt.Errorf("new: auth token: no user id: %w", db.ErrInvalidParameter)
	}
	if authMethodId == "" {
		return nil, fmt.Errorf("new: auth token: no auth method id: %w", db.ErrInvalidParameter)
	}

	s := &AuthToken{
		AuthToken: &store.AuthToken{
			ScopeId:      scopeId,
			IamUserId:    userId,
			AuthMethodId: authMethodId,
		},
	}
	return s, nil
}

func (s *AuthToken) clone() *AuthToken {
	cp := proto.Clone(s.AuthToken)
	return &AuthToken{
		AuthToken: cp.(*store.AuthToken),
	}
}

// EncryptData the entry's data using the provided cipher (wrapping.Wrapper)
func (s *AuthToken) EncryptData(ctx context.Context, cipher wrapping.Wrapper) error {
	// structwrapping doesn't support embedding, so we'll pass in the store.Entry directly
	if err := structwrapping.WrapStruct(ctx, cipher, s.AuthToken, nil); err != nil {
		return fmt.Errorf("error encrypting auth token: %w", err)
	}
	return nil
}

// DecryptData will decrypt the auth token's value using the provided cipher (wrapping.Wrapper)
func (s *AuthToken) DecryptData(ctx context.Context, cipher wrapping.Wrapper) error {
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
)

func newAuthTokenId() (string, error) {
	id, err := db.NewPublicId(AuthTokenPrefix)
	if err != nil {
		return "", fmt.Errorf("new auth token id: %w", err)
	}
	return id, err
}

// newAuthToken generates a token of length 24 not counting the version prefix.
func newAuthToken() (string, error) {
	token, err := base62.Random(24)
	if err != nil {
		return "", fmt.Errorf("Unable to generate auth token: %w", err)
	}
	return fmt.Sprintf("%s%s", TokenValueVersionPrefix, token), nil
}
