package schema

import "fmt"

// MigrationCheckError is an error returned when a migration hook check function
// reports an error.
type MigrationCheckError struct {
	Version           int
	Edition           string
	Err               error
	RepairDescription string
}

func (e MigrationCheckError) Error() string {
	return fmt.Sprintf("%s:%d: %s", e.Edition, e.Version, e.Err.Error())
}
