package kms

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func Test_ExternalKmsType(t *testing.T) {

	tests := []struct {
		typeString string
		want       KmsType
	}{
		{
			typeString: "unknownkms",
			want:       UnknownKms,
		},
		{
			typeString: "aeadkms",
			want:       AeadKms,
		},
		{
			typeString: "awskms",
			want:       AwsKms,
		},
		{
			typeString: "gcpkms",
			want:       GcpKms,
		},
		{
			typeString: "alicloudkms",
			want:       AliCloudKms,
		},
		{
			typeString: "azurekms",
			want:       AzureKms,
		},
		{
			typeString: "ocikms",
			want:       OciKms,
		},
		{
			typeString: "vaulttransitkms",
			want:       VaultTransitKms,
		},
		{
			typeString: "HsmPkcs11Kms",
			want:       HsmPkcs11Kms,
		},
	}
	for _, tt := range tests {
		t.Run(tt.typeString, func(t *testing.T) {
			assert.Equalf(t, tt.want, Map[tt.typeString], "unexpected type for %s", tt.typeString)
			assert.Equalf(t, tt.typeString, tt.want.String(), "unexpected string for %s", tt.typeString)
		})
	}
}
