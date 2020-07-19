package password

import "context"

// A Configuration is an interface holding one of the configuration types
// for a specific key derivation function. Argon2Configuration is currently
// the only configuration type.
type Configuration interface {
	AuthMethodId() string
}

// GetConfiguration returns the current configuration for authMethodId.
func (r *Repository) GetConfiguration(ctx context.Context, authMethodId string) (Configuration, error) {
	panic("not implemented")
}

// SetConfiguration sets the configuration for c.AuthMethodId to c and
// returns a new Configuration. c is not changed. c must contain a valid
// AuthMethodId. c.PublicId is ignored.
//
// If c contains new settings for c.AuthMethodId, SetConfiguration inserts
// c into the repository and updates AuthMethod to use the new
// configuration. If c contains settings equal to the current configuration
// for c.AuthMethodId, SetConfiguration ignores c. If c contains settings
// equal to a previous configuration for c.AuthMethodId, SetConfiguration
// updates AuthMethod to use the previous configuration.
func (r *Repository) SetConfiguration(ctx context.Context, c Configuration) (Configuration, error) {
	panic("not implemented")
}

type currentConfig struct {
	PasswordConfId    string `gorm:"primary_key"`
	PasswordMethodId  string
	ConfType          string
	MinUserNameLength int
	MinPasswordLength int

	*Argon2Configuration
}

func (c *currentConfig) TableName() string {
	return "auth_password_current_conf"
}

func (r *Repository) currentConfig(ctx context.Context, authMethodId string) (*currentConfig, error) {
	var cc currentConfig
	if err := r.reader.LookupWhere(ctx, &cc, "password_method_id = ?", authMethodId); err != nil {
		return nil, err
	}
	return &cc, nil
}

func (c *currentConfig) argon2() *Argon2Configuration {
	if c.ConfType != "argon2" {
		return nil
	}
	return c.Argon2Configuration
}
