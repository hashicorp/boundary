package kms

type KeyPurpose string

const (
	KeyPurposeUnknown  KeyPurpose = "unknown"
	KeyPurposeDatabase KeyPurpose = "database"
	KeyPurposeOplog    KeyPurpose = "oplog"
)

func (k KeyPurpose) String() string {
	return string(k)
}
