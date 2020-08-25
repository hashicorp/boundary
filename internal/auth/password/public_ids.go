package password

import (
	"fmt"

	"github.com/hashicorp/boundary/internal/db"
)

// PublicId prefixes for the resources in the password package.
const (
	AuthMethodPrefix = "ampw"
	AccountPrefix    = "apw"
)

func newAuthMethodId() (string, error) {
	id, err := db.NewPublicId(AuthMethodPrefix)
	if err != nil {
		return "", fmt.Errorf("new password auth method id: %w", err)
	}
	return id, err
}

func newAccountId() (string, error) {
	id, err := db.NewPublicId(AccountPrefix)
	if err != nil {
		return "", fmt.Errorf("new password account id: %w", err)
	}
	return id, err
}
