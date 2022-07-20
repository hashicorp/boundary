package connect

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	typedUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: string(credential.UsernamePasswordType),
		},
		Credential: map[string]interface{}{
			"username": "user",
			"password": "pass",
		},
	}

	typedSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: string(credential.SshPrivateKeyType),
		},
		Credential: map[string]interface{}{
			"username":    "user",
			"private_key": "my-pk",
		},
	}

	vaultUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: "vault",
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]interface{}{
				"username": "vault-decoded-user",
				"password": "vault-decoded-pass",
			},
		},
	}

	vaultSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: "vault",
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]interface{}{
				"username":    "vault-decoded-user",
				"private_key": "vault-decoded-pk",
			},
		},
	}

	staticUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: "static",
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]interface{}{
				"username": "static-decoded-user",
				"password": "static-decoded-pass",
			},
		},
	}

	staticSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: "static",
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]interface{}{
				"username":    "static-decoded-user",
				"private_key": "static-decoded-pk",
			},
		},
	}

	unspecifiedCred = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: "static",
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]interface{}{
				"username":   "decoded-user",
				"some-value": "decoded-some-value",
			},
		},
	}

	unspecifiedCred1 = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: "static",
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]interface{}{
				"username":    "decoded-user",
				"some-value1": "decoded-some-value1",
			},
		},
	}
)

func Test_parseCredentials(t *testing.T) {
	tests := []struct {
		name      string
		creds     []*targets.SessionCredential
		wantCreds credentials
		wantErr   bool
	}{
		{
			name:    "no-creds",
			wantErr: false,
		},
		{
			name: "no-credential-source",
			creds: []*targets.SessionCredential{
				{
					Secret: &targets.SessionSecret{
						Decoded: map[string]interface{}{
							"username":    "decoded-user",
							"private_key": "decoded-pk",
						},
					},
				},
			},
			wantErr: true,
		},
		{
			name: "username-password-typed",
			creds: []*targets.SessionCredential{
				typedUsernamePassword,
			},
			wantCreds: credentials{
				usernamePassword: []usernamePassword{
					{
						Username: "user",
						Password: "pass",
						raw:      typedUsernamePassword,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "ssh-private-key-typed",
			creds: []*targets.SessionCredential{
				typedSshPrivateKey,
			},
			wantCreds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						Username:   "user",
						PrivateKey: "my-pk",
						raw:        typedSshPrivateKey,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "vault-username-password-decoded",
			creds: []*targets.SessionCredential{
				vaultUsernamePassword,
			},
			wantCreds: credentials{
				usernamePassword: []usernamePassword{
					{
						Username: "vault-decoded-user",
						Password: "vault-decoded-pass",
						raw:      vaultUsernamePassword,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "vault-private-key-decoded",
			creds: []*targets.SessionCredential{
				vaultSshPrivateKey,
			},
			wantCreds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						Username:   "vault-decoded-user",
						PrivateKey: "vault-decoded-pk",
						raw:        vaultSshPrivateKey,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "static-username-password-decoded",
			creds: []*targets.SessionCredential{
				staticUsernamePassword,
			},
			wantCreds: credentials{
				usernamePassword: []usernamePassword{
					{
						Username: "static-decoded-user",
						Password: "static-decoded-pass",
						raw:      staticUsernamePassword,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "static-private-key-decoded",
			creds: []*targets.SessionCredential{
				staticSshPrivateKey,
			},
			wantCreds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						Username:   "static-decoded-user",
						PrivateKey: "static-decoded-pk",
						raw:        staticSshPrivateKey,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unspecified",
			creds: []*targets.SessionCredential{
				unspecifiedCred,
			},
			wantCreds: credentials{
				unspecified: []*targets.SessionCredential{
					unspecifiedCred,
				},
			},
			wantErr: false,
		},
		{
			name: "mixed",
			creds: []*targets.SessionCredential{
				staticSshPrivateKey, unspecifiedCred1, vaultSshPrivateKey, typedUsernamePassword,
				unspecifiedCred, vaultUsernamePassword, typedSshPrivateKey, staticUsernamePassword,
			},
			wantCreds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						Username:   "static-decoded-user",
						PrivateKey: "static-decoded-pk",
						raw:        staticSshPrivateKey,
					},
					{
						Username:   "vault-decoded-user",
						PrivateKey: "vault-decoded-pk",
						raw:        vaultSshPrivateKey,
					},
					{
						Username:   "user",
						PrivateKey: "my-pk",
						raw:        typedSshPrivateKey,
					},
				},
				usernamePassword: []usernamePassword{
					{
						Username: "static-decoded-user",
						Password: "static-decoded-pass",
						raw:      staticUsernamePassword,
					},
					{
						Username: "vault-decoded-user",
						Password: "vault-decoded-pass",
						raw:      vaultUsernamePassword,
					},
					{
						Username: "user",
						Password: "pass",
						raw:      typedUsernamePassword,
					},
				},
				unspecified: []*targets.SessionCredential{
					unspecifiedCred, unspecifiedCred1,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			creds, err := parseCredentials(tt.creds)
			if tt.wantErr {
				require.Error(err)
				assert.Empty(creds)
				return
			}
			require.NoError(err)

			assert.ElementsMatch(tt.wantCreds.usernamePassword, creds.usernamePassword)
			assert.ElementsMatch(tt.wantCreds.sshPrivateKey, creds.sshPrivateKey)
			assert.ElementsMatch(tt.wantCreds.unspecified, creds.unspecified)
		})
	}
}

func Test_unconsumedSessionCredentials(t *testing.T) {
	tests := []struct {
		name      string
		creds     credentials
		wantCreds []*targets.SessionCredential
	}{
		{
			name:      "no-creds",
			wantCreds: nil,
		},
		{
			name: "spk-consumed",
			creds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						raw:      staticSshPrivateKey,
						consumed: true,
					},
				},
			},
			wantCreds: nil,
		},
		{
			name: "spk",
			creds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						raw: staticSshPrivateKey,
					},
				},
			},
			wantCreds: []*targets.SessionCredential{staticSshPrivateKey},
		},
		{
			name: "up",
			creds: credentials{
				usernamePassword: []usernamePassword{
					{
						raw: vaultUsernamePassword,
					},
				},
			},
			wantCreds: []*targets.SessionCredential{vaultUsernamePassword},
		},
		{
			name: "up-consumed",
			creds: credentials{
				usernamePassword: []usernamePassword{
					{
						raw:      vaultUsernamePassword,
						consumed: true,
					},
				},
			},
			wantCreds: nil,
		},
		{
			name: "unspecified",
			creds: credentials{
				unspecified: []*targets.SessionCredential{unspecifiedCred},
			},
			wantCreds: []*targets.SessionCredential{unspecifiedCred},
		},
		{
			name: "mixed",
			creds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						raw:      staticSshPrivateKey,
						consumed: true,
					},
					{
						raw: vaultSshPrivateKey,
					},
					{
						raw: typedSshPrivateKey,
					},
				},
				usernamePassword: []usernamePassword{
					{
						raw:      staticUsernamePassword,
						consumed: true,
					},
					{
						raw: vaultUsernamePassword,
					},
					{
						raw:      typedUsernamePassword,
						consumed: true,
					},
				},
				unspecified: []*targets.SessionCredential{unspecifiedCred, unspecifiedCred1},
			},
			wantCreds: []*targets.SessionCredential{
				vaultSshPrivateKey, typedSshPrivateKey, vaultUsernamePassword, unspecifiedCred, unspecifiedCred1,
			},
		},
		{
			name: "mixed-all-consumed",
			creds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						raw:      staticSshPrivateKey,
						consumed: true,
					},
					{
						raw:      vaultSshPrivateKey,
						consumed: true,
					},
					{
						raw:      typedSshPrivateKey,
						consumed: true,
					},
				},
				usernamePassword: []usernamePassword{
					{
						raw:      staticUsernamePassword,
						consumed: true,
					},
					{
						raw:      vaultUsernamePassword,
						consumed: true,
					},
					{
						raw:      typedUsernamePassword,
						consumed: true,
					},
				},
				unspecified: []*targets.SessionCredential{unspecifiedCred, unspecifiedCred1},
			},
			wantCreds: []*targets.SessionCredential{
				unspecifiedCred1, unspecifiedCred,
			},
		},
		{
			name: "mixed-all-unconsumed",
			creds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						raw: staticSshPrivateKey,
					},
					{
						raw: vaultSshPrivateKey,
					},
					{
						raw: typedSshPrivateKey,
					},
				},
				usernamePassword: []usernamePassword{
					{
						raw: staticUsernamePassword,
					},
					{
						raw: vaultUsernamePassword,
					},
					{
						raw: typedUsernamePassword,
					},
				},
				unspecified: []*targets.SessionCredential{unspecifiedCred, unspecifiedCred1},
			},
			wantCreds: []*targets.SessionCredential{
				staticSshPrivateKey, unspecifiedCred1, vaultSshPrivateKey, typedUsernamePassword,
				unspecifiedCred, vaultUsernamePassword, typedSshPrivateKey, staticUsernamePassword,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			creds := tt.creds.unconsumedSessionCredentials()
			assert.ElementsMatch(tt.wantCreds, creds)
		})
	}
}
