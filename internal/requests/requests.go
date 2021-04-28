package requests

import "github.com/hashicorp/boundary/internal/perms"

// ContextRequestInforation is a type used solely for context keys -- see the
// variable below
type ContextRequestInformation struct{}

// ContextRequestInformationKey is a value to keep linters from complaining
// about clashing identifiers
var ContextRequestInformationKey ContextRequestInformation

// RequestInfo is used to propoagate request information. It can be updated at
// various points, e.g. UserIsAnonymous would be updated via the result of
// auth.Verify.
type RequestInfo struct {
	// UserId contains the final discovered user ID
	UserId string

	// OutputFields is the set of fields authorized for output for the
	// authorized action, if not the default
	OutputFields perms.OutputFieldsMap
}
