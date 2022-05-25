package kms

import (
	wrapping "github.com/hashicorp/go-kms-wrapping/v2"
)

// ExternalWrappers holds wrappers defined outside of Boundary, e.g. in its
// configuration file.
type ExternalWrappers struct {
	root       wrapping.Wrapper
	workerAuth wrapping.Wrapper
	recovery   wrapping.Wrapper
}

// Root returns the wrapper for root keys
func (e *ExternalWrappers) Root() wrapping.Wrapper {
	return e.root
}

// WorkerAuth returns the wrapper for worker authentication
func (e *ExternalWrappers) WorkerAuth() wrapping.Wrapper {
	return e.workerAuth
}

// Recovery returns the wrapper for recovery operations
func (e *ExternalWrappers) Recovery() wrapping.Wrapper {
	return e.recovery
}
