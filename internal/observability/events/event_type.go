package event

// Type represents the event's type
type Type string

const (
	EveryType       Type = "*"           // EveryType represents every (all) types of events
	ObservationType Type = "observation" // ObservationType represents observation events
	AuditType       Type = "audit"       // AuditType represents audit events
	ErrorType       Type = "error"       // ErrorType represents error events
)
