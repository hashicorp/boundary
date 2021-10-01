package credential

// Mapping represents the mapping a credential library should use to
// Issue a strongly typed credential
type Mapping interface{}

// UserPasswordMapping maps a credential to a credential.UserPassword
type UserPasswordMapping struct {
	Username string
	Password string
}
