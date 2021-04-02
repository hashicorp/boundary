package vault

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/credential/vault/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// certPen and keyPem are copied from crypto/tls/example_test.go in the Go
// standard library.
const (
	certPem = `-----BEGIN CERTIFICATE-----
MIIBhTCCASugAwIBAgIQIRi6zePL6mKjOipn+dNuaTAKBggqhkjOPQQDAjASMRAw
DgYDVQQKEwdBY21lIENvMB4XDTE3MTAyMDE5NDMwNloXDTE4MTAyMDE5NDMwNlow
EjEQMA4GA1UEChMHQWNtZSBDbzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABD0d
7VNhbWvZLWPuj/RtHFjvtJBEwOkhbN/BnnE8rnZR8+sbwnc/KhCk3FhnpHZnQz7B
5aETbbIgmuvewdjvSBSjYzBhMA4GA1UdDwEB/wQEAwICpDATBgNVHSUEDDAKBggr
BgEFBQcDATAPBgNVHRMBAf8EBTADAQH/MCkGA1UdEQQiMCCCDmxvY2FsaG9zdDo1
NDUzgg4xMjcuMC4wLjE6NTQ1MzAKBggqhkjOPQQDAgNIADBFAiEA2zpJEPQyz6/l
Wf86aX6PepsntZv2GYlA5UpabfT2EZICICpJ5h/iI+i341gBmLiAFQOyTDT+/wQc
6MF9+Yw1Yy0t
-----END CERTIFICATE-----`

	keyPem = `-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIIrYSSNQFaA2Hwf1duRSxKtLYX5CB04fSeQ6tF1aY/PuoAoGCCqGSM49
AwEHoUQDQgAEPR3tU2Fta9ktY+6P9G0cWO+0kETA6SFs38GecTyudlHz6xvCdz8q
EKTcWGekdmdDPsHloRNtsiCa697B2O9IFA==
-----END EC PRIVATE KEY-----`
)

func TestClientCertificate_New(t *testing.T) {
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	rw := db.New(conn)

	kkms := kms.TestKms(t, conn, wrapper)

	_, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	cs := TestCredentialStores(t, conn, wrapper, prj.PublicId, 1)[0]

	type args struct {
		storeId     string
		certificate []byte
		key         []byte
	}

	tests := []struct {
		name    string
		args    args
		want    *ClientCertificate
		wantErr bool
	}{
		{
			name: "blank-store-id",
			args: args{
				storeId:     "",
				certificate: []byte(certPem),
				key:         []byte(keyPem),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-certificate",
			args: args{
				storeId: cs.PublicId,
				key:     []byte(keyPem),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "missing-key",
			args: args{
				storeId:     cs.PublicId,
				certificate: []byte(certPem),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid",
			args: args{
				storeId:     cs.PublicId,
				certificate: []byte(certPem),
				key:         []byte(keyPem),
			},
			want: &ClientCertificate{
				ClientCertificate: &store.ClientCertificate{
					StoreId:        cs.PublicId,
					Certificate:    []byte(certPem),
					CertificateKey: []byte(keyPem),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			ctx := context.Background()
			databaseWrapper, err := kkms.GetWrapper(ctx, prj.PublicId, kms.KeyPurposeDatabase)
			require.NoError(err)
			require.NotNil(databaseWrapper)

			got, err := newClientCertificate(tt.args.storeId, tt.args.certificate, tt.args.key)
			if tt.wantErr {
				assert.Error(err)
				require.Nil(got)
				return
			}
			require.NoError(err)
			require.NotNil(got)

			want := tt.want
			assert.Empty(got.CtCertificateKey)
			assert.Equal(want, got)

			require.NoError(got.encrypt(ctx, databaseWrapper))

			err2 := rw.Create(context.Background(), got)
			assert.NoError(err2)
		})
	}
}
