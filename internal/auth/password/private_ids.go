package password

import (
	"fmt"

	"github.com/hashicorp/watchtower/internal/db"
)

// Prefixes for private ids for types in the password package.
const (
	argon2ConfigurationPrefix = "arg2conf"
)

func newArgon2ConfigurationId() (string, error) {
	id, err := db.NewPrivateId(argon2ConfigurationPrefix)
	if err != nil {
		return "", fmt.Errorf("new password argon2 configuration id: %w", err)
	}
	return id, err
}
