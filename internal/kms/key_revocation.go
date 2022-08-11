package kms

import (
	"github.com/hashicorp/boundary/internal/kms/store"
)

type KeyRevocationStatus int

const (
	KeyRevocationStatusUnspecified KeyRevocationStatus = iota
	KeyRevocationStatusPending
	KeyRevocationStatusRunning
	KeyRevocationStatusCompleted
	KeyRevocationStatusFailed
)

func (k KeyRevocationStatus) String() string {
	return [...]string{
		"unspecified",
		"pending",
		"running",
		"completed",
		"failed",
	}[k]
}

type KeyRevocation struct {
	*store.KeyRevocation
}

func (k *KeyRevocation) TableName() string {
	return "kms_key_revocations"
}
