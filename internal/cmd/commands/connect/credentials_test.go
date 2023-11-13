// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package connect

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/hashicorp/boundary/internal/credential/static"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	typedUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: string(credential.UsernamePasswordType),
		},
		Credential: map[string]any{
			"username": "user",
			"password": "pass",
		},
	}

	typedSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: string(credential.SshPrivateKeyType),
		},
		Credential: map[string]any{
			"username":    "user",
			"private_key": "my-pk",
		},
	}

	vaultUsernamePasswordDeprecatedSubtype = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: vault.Subtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username": "vault-decoded-user",
				"password": "vault-decoded-pass",
			},
		},
	}

	vaultSshPrivateKeyDeprecatedSubtype = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: vault.Subtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username":    "vault-decoded-user",
				"private_key": "vault-decoded-pk",
			},
		},
	}

	vaultUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: vault.GenericLibrarySubtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username": "vault-decoded-user",
				"password": "vault-decoded-pass",
			},
		},
	}

	vaultSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: vault.GenericLibrarySubtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username":    "vault-decoded-user",
				"private_key": "vault-decoded-pk",
			},
		},
	}

	unknownUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username": "unknown-decoded-user",
				"password": "unknown-decoded-pass",
			},
		},
	}

	unknownSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username":    "unknown-decoded-user",
				"private_key": "unknown-decoded-pk",
			},
		},
	}

	staticUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: static.Subtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username": "static-decoded-user",
				"password": "static-decoded-pass",
			},
		},
	}

	staticSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: static.Subtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username":    "static-decoded-user",
				"private_key": "static-decoded-pk",
			},
		},
	}

	staticKv = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type:              static.Subtype.String(),
			CredentialType:    "json",
			CredentialStoreId: "csst_id",
			Description:       "test",
			Name:              "test unspecified json cred",
			Id:                "credjson_id",
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"secret": map[string]any{
					"username": "password",
				},
			},
		},
	}

	unspecifiedCred = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: static.Subtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username":   "decoded-user",
				"some-value": "decoded-some-value",
			},
		},
	}

	unspecifiedCred1 = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: static.Subtype.String(),
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
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
						Decoded: map[string]any{
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
			name: "vault-deprecated-username-password-decoded",
			creds: []*targets.SessionCredential{
				vaultUsernamePasswordDeprecatedSubtype,
			},
			wantCreds: credentials{
				usernamePassword: []usernamePassword{
					{
						Username: "vault-decoded-user",
						Password: "vault-decoded-pass",
						raw:      vaultUsernamePasswordDeprecatedSubtype,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "vault-deprecated-private-key-decoded",
			creds: []*targets.SessionCredential{
				vaultSshPrivateKeyDeprecatedSubtype,
			},
			wantCreds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						Username:   "vault-decoded-user",
						PrivateKey: "vault-decoded-pk",
						raw:        vaultSshPrivateKeyDeprecatedSubtype,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unknown-username-password-decoded",
			creds: []*targets.SessionCredential{
				unknownUsernamePassword,
			},
			wantCreds: credentials{
				usernamePassword: []usernamePassword{
					{
						Username: "unknown-decoded-user",
						Password: "unknown-decoded-pass",
						raw:      unknownUsernamePassword,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "unknown-private-key-decoded",
			creds: []*targets.SessionCredential{
				unknownSshPrivateKey,
			},
			wantCreds: credentials{
				sshPrivateKey: []sshPrivateKey{
					{
						Username:   "unknown-decoded-user",
						PrivateKey: "unknown-decoded-pk",
						raw:        unknownSshPrivateKey,
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
			name: "unspecified-static-json",
			creds: []*targets.SessionCredential{
				staticKv,
			},
			wantCreds: credentials{
				unspecified: []*targets.SessionCredential{
					staticKv,
				},
			},
			wantErr: false,
		},
		{
			name: "mixed",
			creds: []*targets.SessionCredential{
				staticSshPrivateKey, unspecifiedCred1, vaultSshPrivateKey, typedUsernamePassword,
				unspecifiedCred, vaultUsernamePassword, typedSshPrivateKey, staticUsernamePassword,
				staticKv,
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
					unspecifiedCred, unspecifiedCred1, staticKv,
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
