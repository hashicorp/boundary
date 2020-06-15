package usersessions

import (
	"fmt"

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

// NewSession creates a new in memory Session assigned to scopeId.
// Name and description are the only valid options. All other options are
// ignored.
func NewSession(scopeId, userId, authMethodId string, opt ...Option) (*Session, error) {
	if scopeId == "" {
		return nil, fmt.Errorf("new: static host catalog: no scope id: %w", db.ErrInvalidParameter)
	}

	hc := &Session{
		Session: &store.Session{
			IamScopeId:   scopeId,
			IamUserId:    userId,
			AuthMethodId: authMethodId,
		},
	}
	return hc, nil
}

func (c *Session) clone() *Session {
	cp := proto.Clone(c.Session)
	return &Session{
		Session: cp.(*store.Session),
	}
}

// PublicId prefixes for the resources in the static package.
const (
	SessionPrefix      = "sess"
	SessionTokenPrefix = "sesstok"
)

func newSessionId() (string, error) {
	id, err := db.NewPublicId(SessionPrefix)
	if err != nil {
		return "", fmt.Errorf("new session id: %w", err)
	}
	return id, err
}

func newSessionToken() (string, error) {
	id, err := db.NewPublicId(SessionTokenPrefix)
	if err != nil {
		return "", fmt.Errorf("new session token: %w", err)
	}
	return id, err
}
