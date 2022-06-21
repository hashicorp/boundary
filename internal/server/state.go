package server

// CertificateState defines the possible states for a workerauth certificate
type CertificateState string

const (
	UnknownState CertificateState = "unknown"
	CurrentState CertificateState = "current"
	NextState    CertificateState = "next"
)

func validState(s CertificateState) bool {
	st := CertificateState(s)
	switch st {
	case CurrentState, NextState:
		return true
	default:
		return false
	}
}
