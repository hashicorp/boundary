package password

import "context"

// A Configuration is an interface holding one of the configuration types
// for a specific key derivation function. Argon2Configuration is currently
// the only configuration type.
type Configuration interface{}

// GetConfiguration returns the current configuration for authMethodId.
func (r *Repository) GetConfiguration(ctx context.Context, authMethodId string) (Configuration, error) {
	panic("not implemented")
}

// SetConfiguration sets the configuration for authMethodId to c.
func (r *Repository) SetConfiguration(ctx context.Context, authMethodId string, c Configuration) error {
	panic("not implemented")
}
