// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: MPL-2.0

package proxy

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	staticSubtype                     = "static"
	vaultSubtype                      = "vault"
	vaultGenericLibrarySubtype        = "vault-generic"
	vaultSshCertificateLibrarySubtype = "vault-ssh-certificate"
)

var (
	typedUsernamePassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: usernamePasswordCredentialType,
		},
		Credential: map[string]any{
			"username": "user",
			"password": "pass",
		},
	}

	typedPassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: passwordCredentialType,
		},
		Credential: map[string]any{
			"password": "pass",
		},
	}

	typedSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			CredentialType: sshPrivateKeyCredentialType,
		},
		Credential: map[string]any{
			"username":    "user",
			"private_key": "my-pk",
		},
	}

	vaultUsernamePasswordDeprecatedSubtype = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: vaultSubtype,
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
			Type: vaultSubtype,
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
			Type: vaultGenericLibrarySubtype,
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username": "vault-decoded-user",
				"password": "vault-decoded-pass",
			},
		},
	}

	vaultPassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: vaultGenericLibrarySubtype,
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"password": "vault-decoded-pass",
			},
		},
	}

	vaultSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: vaultGenericLibrarySubtype,
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
			Type: staticSubtype,
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username": "static-decoded-user",
				"password": "static-decoded-pass",
			},
		},
	}

	staticPassword = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: staticSubtype,
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"password": "static-decoded-pass",
			},
		},
	}

	staticSshPrivateKey = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: staticSubtype,
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
			Type:              staticSubtype,
			CredentialType:    "json",
			CredentialStoreId: "csst_id",
			Description:       "test",
			Name:              "test Unspecified json cred",
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

	UnspecifiedCred = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: staticSubtype,
		},
		Secret: &targets.SessionSecret{
			Decoded: map[string]any{
				"username":   "decoded-user",
				"some-value": "decoded-some-value",
			},
		},
	}

	UnspecifiedCred1 = &targets.SessionCredential{
		CredentialSource: &targets.CredentialSource{
			Type: staticSubtype,
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
		wantCreds Credentials
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
			wantCreds: Credentials{
				UsernamePassword: []UsernamePassword{
					{
						Username: "user",
						Password: "pass",
						Raw:      typedUsernamePassword,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "password-typed",
			creds: []*targets.SessionCredential{
				typedPassword,
			},
			wantCreds: Credentials{
				Password: []Password{
					{
						Password: "pass",
						Raw:      typedPassword,
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
			wantCreds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Username:   "user",
						PrivateKey: "my-pk",
						Raw:        typedSshPrivateKey,
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
			wantCreds: Credentials{
				UsernamePassword: []UsernamePassword{
					{
						Username: "vault-decoded-user",
						Password: "vault-decoded-pass",
						Raw:      vaultUsernamePassword,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "vault-password-decoded",
			creds: []*targets.SessionCredential{
				vaultPassword,
			},
			wantCreds: Credentials{
				Password: []Password{
					{
						Password: "vault-decoded-pass",
						Raw:      vaultPassword,
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
			wantCreds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Username:   "vault-decoded-user",
						PrivateKey: "vault-decoded-pk",
						Raw:        vaultSshPrivateKey,
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
			wantCreds: Credentials{
				UsernamePassword: []UsernamePassword{
					{
						Username: "vault-decoded-user",
						Password: "vault-decoded-pass",
						Raw:      vaultUsernamePasswordDeprecatedSubtype,
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
			wantCreds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Username:   "vault-decoded-user",
						PrivateKey: "vault-decoded-pk",
						Raw:        vaultSshPrivateKeyDeprecatedSubtype,
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
			wantCreds: Credentials{
				UsernamePassword: []UsernamePassword{
					{
						Username: "unknown-decoded-user",
						Password: "unknown-decoded-pass",
						Raw:      unknownUsernamePassword,
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
			wantCreds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Username:   "unknown-decoded-user",
						PrivateKey: "unknown-decoded-pk",
						Raw:        unknownSshPrivateKey,
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
			wantCreds: Credentials{
				UsernamePassword: []UsernamePassword{
					{
						Username: "static-decoded-user",
						Password: "static-decoded-pass",
						Raw:      staticUsernamePassword,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "static-password-decoded",
			creds: []*targets.SessionCredential{
				staticPassword,
			},
			wantCreds: Credentials{
				Password: []Password{
					{
						Password: "static-decoded-pass",
						Raw:      staticPassword,
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
			wantCreds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Username:   "static-decoded-user",
						PrivateKey: "static-decoded-pk",
						Raw:        staticSshPrivateKey,
					},
				},
			},
			wantErr: false,
		},
		{
			name: "Unspecified",
			creds: []*targets.SessionCredential{
				UnspecifiedCred,
			},
			wantCreds: Credentials{
				Unspecified: []*targets.SessionCredential{
					UnspecifiedCred,
				},
			},
			wantErr: false,
		},
		{
			name: "Unspecified-static-json",
			creds: []*targets.SessionCredential{
				staticKv,
			},
			wantCreds: Credentials{
				Unspecified: []*targets.SessionCredential{
					staticKv,
				},
			},
			wantErr: false,
		},
		{
			name: "mixed",
			creds: []*targets.SessionCredential{
				staticSshPrivateKey, UnspecifiedCred1, vaultSshPrivateKey, typedUsernamePassword,
				UnspecifiedCred, vaultUsernamePassword, typedSshPrivateKey, staticUsernamePassword,
				staticKv, typedPassword, vaultPassword, staticPassword,
			},
			wantCreds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Username:   "static-decoded-user",
						PrivateKey: "static-decoded-pk",
						Raw:        staticSshPrivateKey,
					},
					{
						Username:   "vault-decoded-user",
						PrivateKey: "vault-decoded-pk",
						Raw:        vaultSshPrivateKey,
					},
					{
						Username:   "user",
						PrivateKey: "my-pk",
						Raw:        typedSshPrivateKey,
					},
				},
				UsernamePassword: []UsernamePassword{
					{
						Username: "static-decoded-user",
						Password: "static-decoded-pass",
						Raw:      staticUsernamePassword,
					},
					{
						Username: "vault-decoded-user",
						Password: "vault-decoded-pass",
						Raw:      vaultUsernamePassword,
					},
					{
						Username: "user",
						Password: "pass",
						Raw:      typedUsernamePassword,
					},
				},
				Password: []Password{
					{
						Password: "static-decoded-pass",
						Raw:      staticPassword,
					},
					{
						Password: "vault-decoded-pass",
						Raw:      vaultPassword,
					},
					{
						Password: "pass",
						Raw:      typedPassword,
					},
				},
				Unspecified: []*targets.SessionCredential{
					UnspecifiedCred, UnspecifiedCred1, staticKv,
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			creds, err := ParseCredentials(tt.creds)
			if tt.wantErr {
				require.Error(err)
				assert.Empty(creds)
				return
			}
			require.NoError(err)

			assert.ElementsMatch(tt.wantCreds.UsernamePassword, creds.UsernamePassword)
			assert.ElementsMatch(tt.wantCreds.SshPrivateKey, creds.SshPrivateKey)
			assert.ElementsMatch(tt.wantCreds.Unspecified, creds.Unspecified)
			assert.ElementsMatch(tt.wantCreds.Password, creds.Password)
		})
	}
}

func Test_unconsumedSessionCredentials(t *testing.T) {
	tests := []struct {
		name      string
		creds     Credentials
		wantCreds []*targets.SessionCredential
	}{
		{
			name:      "no-creds",
			wantCreds: nil,
		},
		{
			name: "spk-consumed",
			creds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Raw:      staticSshPrivateKey,
						Consumed: true,
					},
				},
			},
			wantCreds: nil,
		},
		{
			name: "spk",
			creds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Raw: staticSshPrivateKey,
					},
				},
			},
			wantCreds: []*targets.SessionCredential{staticSshPrivateKey},
		},
		{
			name: "up",
			creds: Credentials{
				UsernamePassword: []UsernamePassword{
					{
						Raw: vaultUsernamePassword,
					},
				},
			},
			wantCreds: []*targets.SessionCredential{vaultUsernamePassword},
		},
		{
			name: "up-consumed",
			creds: Credentials{
				UsernamePassword: []UsernamePassword{
					{
						Raw:      vaultUsernamePassword,
						Consumed: true,
					},
				},
			},
			wantCreds: nil,
		},
		{
			name: "p",
			creds: Credentials{
				Password: []Password{
					{
						Raw: vaultPassword,
					},
				},
			},
			wantCreds: []*targets.SessionCredential{vaultPassword},
		},
		{
			name: "p-consumed",
			creds: Credentials{
				Password: []Password{
					{
						Raw:      vaultPassword,
						Consumed: true,
					},
				},
			},
			wantCreds: nil,
		},
		{
			name: "Unspecified",
			creds: Credentials{
				Unspecified: []*targets.SessionCredential{UnspecifiedCred},
			},
			wantCreds: []*targets.SessionCredential{UnspecifiedCred},
		},
		{
			name: "mixed",
			creds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Raw:      staticSshPrivateKey,
						Consumed: true,
					},
					{
						Raw: vaultSshPrivateKey,
					},
					{
						Raw: typedSshPrivateKey,
					},
				},
				UsernamePassword: []UsernamePassword{
					{
						Raw:      staticUsernamePassword,
						Consumed: true,
					},
					{
						Raw: vaultUsernamePassword,
					},
					{
						Raw:      typedUsernamePassword,
						Consumed: true,
					},
				},
				Password: []Password{
					{
						Raw: staticPassword,
					},
					{
						Raw: vaultPassword,
					},
					{
						Raw:      typedPassword,
						Consumed: true,
					},
				},
				Unspecified: []*targets.SessionCredential{UnspecifiedCred, UnspecifiedCred1},
			},
			wantCreds: []*targets.SessionCredential{
				vaultSshPrivateKey, typedSshPrivateKey, vaultUsernamePassword, UnspecifiedCred, UnspecifiedCred1,
				staticPassword, vaultPassword,
			},
		},
		{
			name: "mixed-all-consumed",
			creds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Raw:      staticSshPrivateKey,
						Consumed: true,
					},
					{
						Raw:      vaultSshPrivateKey,
						Consumed: true,
					},
					{
						Raw:      typedSshPrivateKey,
						Consumed: true,
					},
				},
				UsernamePassword: []UsernamePassword{
					{
						Raw:      staticUsernamePassword,
						Consumed: true,
					},
					{
						Raw:      vaultUsernamePassword,
						Consumed: true,
					},
					{
						Raw:      typedUsernamePassword,
						Consumed: true,
					},
				},
				Password: []Password{
					{
						Raw:      staticPassword,
						Consumed: true,
					},
					{
						Raw:      vaultPassword,
						Consumed: true,
					},
					{
						Raw:      typedPassword,
						Consumed: true,
					},
				},
				Unspecified: []*targets.SessionCredential{UnspecifiedCred, UnspecifiedCred1},
			},
			wantCreds: []*targets.SessionCredential{
				UnspecifiedCred1, UnspecifiedCred,
			},
		},
		{
			name: "mixed-all-unconsumed",
			creds: Credentials{
				SshPrivateKey: []SshPrivateKey{
					{
						Raw: staticSshPrivateKey,
					},
					{
						Raw: vaultSshPrivateKey,
					},
					{
						Raw: typedSshPrivateKey,
					},
				},
				UsernamePassword: []UsernamePassword{
					{
						Raw: staticUsernamePassword,
					},
					{
						Raw: vaultUsernamePassword,
					},
					{
						Raw: typedUsernamePassword,
					},
				},
				Password: []Password{
					{
						Raw: staticPassword,
					},
					{
						Raw: vaultPassword,
					},
					{
						Raw: typedPassword,
					},
				},
				Unspecified: []*targets.SessionCredential{UnspecifiedCred, UnspecifiedCred1},
			},
			wantCreds: []*targets.SessionCredential{
				staticSshPrivateKey, UnspecifiedCred1, vaultSshPrivateKey, typedUsernamePassword,
				UnspecifiedCred, vaultUsernamePassword, typedSshPrivateKey, staticUsernamePassword,
				staticPassword, vaultPassword, typedPassword,
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)

			creds := tt.creds.UnconsumedSessionCredentials()
			assert.ElementsMatch(tt.wantCreds, creds)
		})
	}
}
