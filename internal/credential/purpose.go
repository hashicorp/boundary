package credential

// Purpose is the purpose of the credential.
type Purpose string

const (
	ApplicationPurpose Purpose = "application"
	IngressPurpose     Purpose = "ingress"
	EgressPurpose      Purpose = "egress"
)
