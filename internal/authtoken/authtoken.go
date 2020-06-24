package authtoken

import (
	"fmt"

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

const (
	AuthTokenPublicIdPrefix = "s"
	AuthTokenPrefix         = "t"
)

func newAuthTokenId() (string, error) {
	id, err := db.NewPublicId(AuthTokenPublicIdPrefix)
	if err != nil {
		return "", fmt.Errorf("new auth token id: %w", err)
	}
	return id, err
}

// newAuthToken generates a token of length 20 not counting the prefix.
func newAuthToken() (string, error) {
	// TODO: figure out if this provides enough randomness.
	token, err := base62.Random(30)
	if err != nil {
		return "", fmt.Errorf("Unable to generate auth token: %w", err)
	}
	return fmt.Sprintf("%s_%s", AuthTokenPrefix, token), nil
}
