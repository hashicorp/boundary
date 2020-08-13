package kms

// Type defines the types of resources in the system
type KmsType int

const (
	UnknownKms      KmsType = 0
	DevKms          KmsType = 1
	AwsKms          KmsType = 2
	GcpKms          KmsType = 3
	AliCloudKms     KmsType = 4
	AzureKms        KmsType = 5
	OciKms          KmsType = 6
	VaultTransitKms KmsType = 7
	HsmPkcs11Kms    KmsType = 8
)

func (k KmsType) String() string {
	return [...]string{
		"unknownkms",
		"devkms",
		"awskms",
		"gcpkms",
		"alicloudkms",
		"azurekms",
		"ocikms",
		"vaulttransitkms",
		"HsmPkcs11Kms",
	}[k]
}

var Map = map[string]KmsType{
	UnknownKms.String():      UnknownKms,
	DevKms.String():          DevKms,
	AwsKms.String():          AwsKms,
	GcpKms.String():          GcpKms,
	AliCloudKms.String():     AliCloudKms,
	AzureKms.String():        AzureKms,
	OciKms.String():          OciKms,
	VaultTransitKms.String(): VaultTransitKms,
	HsmPkcs11Kms.String():    HsmPkcs11Kms,
}
