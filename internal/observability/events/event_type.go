package event

type Type string

const (
	EveryType       Type = "*"
	ObservationType Type = "observation"
	AuditType       Type = "audit"
	ErrorType       Type = "error"
)
