package usersessions

import (
	"fmt"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/usersessions/store"
	"google.golang.org/protobuf/proto"
)

// A Session contains static hosts and static host sets. It is owned by
// a scope.
type Session struct {
	*store.Session
	tableName string `gorm:"-"`
}

// NewSession creates a new in memory Session assigned to scopeId for the user id and authmethod used.
// All options are ignored.
func NewSession(scopeId, userId, authMethodId string, opt ...Option) (*Session, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new: static host catalog: no scope id: %w", db.ErrInvalidParameter)
	}
	if userId == "" {
		return nil, fmt.Errorf("new: static host catalog: no user id: %w", db.ErrInvalidParameter)
	}
	if authMethodId == "" {
		return nil, fmt.Errorf("new: static host catalog: no auth method id: %w", db.ErrInvalidParameter)
	}

	s := &Session{
		Session: &store.Session{
			ScopeId:      scopeId,
			IamUserId:    userId,
			AuthMethodId: authMethodId,
		},
	}
	return s, nil
}

func (s *Session) clone() *Session {
	cp := proto.Clone(s.Session)
	return &Session{
		Session: cp.(*store.Session),
	}
}

// PublicId prefixes for the resources in the static package.
const (
	SessionPrefix      = "s"
	SessionTokenPrefix = "t"
)

func newSessionId() (string, error) {
	id, err := db.NewPublicId(SessionPrefix)
	if err != nil {
		return "", fmt.Errorf("new session id: %w", err)
	}
	return id, err
}

// newSessionToken generates a token of length 20 not counting the session token prefix.
func newSessionToken() (string, error) {
	// TODO: figure out if this provides enough randomness.
	token, err := base62.Random(30)
	if err != nil {
		return "", fmt.Errorf("Unable to generate session token: %w", err)
	}
	return fmt.Sprintf("%s_%s", SessionTokenPrefix, token), nil
}
