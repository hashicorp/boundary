package authtoken

// State of the AuthToken.  It will default IssuedState in the database.
type State string

const (
	// UnknownState for the token.
	UnknownState State = "unknown"

	// PendingState means that the token has been created but it pending while
	// waiting to be issued.
	PendingState State = "auth token pending"

	// IssuedState means the token has been issued.  It is a final state for the
	// token.
	IssuedState State = "token issued"

	// FailedState means the token is in a failed state before it was issued and
	// this is a final state.
	FailedState State = "authentication failed"

	// SystemErrorState means that the system encountered an error before
	// issuing the token. This is a final state.
	SystemErrorState State = "system error"
)
