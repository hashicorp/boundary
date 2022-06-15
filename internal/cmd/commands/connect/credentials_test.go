package connect

import (
	"testing"

	"github.com/hashicorp/boundary/api/targets"
	"github.com/hashicorp/boundary/internal/credential"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_parseUsernamePasswordCredentials(t *testing.T) {
	tests := []struct {
		name      string
		creds     []*targets.SessionCredential
		wantCreds []usernamePasswordCredentials
		wantErr   bool
	}{
		{
			name:      "no-creds",
			wantCreds: nil,
			wantErr:   false,
		},
		{
			name: "no-credential-source",
			creds: []*targets.SessionCredential{
				{
					Credential: map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
			},
			wantCreds: nil,
			wantErr:   true,
		},
		{
			name: "valid-typed",
			creds: []*targets.SessionCredential{
				{
					CredentialSource: &targets.CredentialSource{
						CredentialType: string(credential.UsernamePasswordType),
					},
					Credential: map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
			},
			wantCreds: []usernamePasswordCredentials{
				{
					Username: "user",
					Password: "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "valid-typed-instead-of-decoded",
			creds: []*targets.SessionCredential{
				{
					CredentialSource: &targets.CredentialSource{
						CredentialType: string(credential.UsernamePasswordType),
					},
					Credential: map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
					Secret: &targets.SessionSecret{
						Decoded: map[string]interface{}{
							"username": "secret-user",
							"password": "secret-pass",
						},
					},
				},
			},
			wantCreds: []usernamePasswordCredentials{
				{
					Username: "user",
					Password: "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "valid-vault-not-typed",
			creds: []*targets.SessionCredential{
				{
					CredentialSource: &targets.CredentialSource{
						Type: "vault",
					},
					Secret: &targets.SessionSecret{
						Decoded: map[string]interface{}{
							"username": "user",
							"password": "pass",
						},
					},
				},
			},
			wantCreds: []usernamePasswordCredentials{
				{
					Username: "user",
					Password: "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "valid-static-not-typed",
			creds: []*targets.SessionCredential{
				{
					CredentialSource: &targets.CredentialSource{
						Type: "static",
					},
					Secret: &targets.SessionSecret{
						Decoded: map[string]interface{}{
							"username": "user",
							"password": "pass",
						},
					},
				},
			},
			wantCreds: []usernamePasswordCredentials{
				{
					Username: "user",
					Password: "pass",
				},
			},
			wantErr: false,
		},
		{
			name: "valid-multiple",
			creds: []*targets.SessionCredential{
				{
					CredentialSource: &targets.CredentialSource{
						CredentialType: string(credential.UsernamePasswordType),
					},
					Credential: map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
				{
					CredentialSource: &targets.CredentialSource{
						CredentialType: string(credential.UsernamePasswordType),
					},
					Credential: map[string]interface{}{
						"username": "user1",
						"password": "pass1",
					},
				},
			},
			wantCreds: []usernamePasswordCredentials{
				{
					Username: "user",
					Password: "pass",
				},
				{
					Username: "user1",
					Password: "pass1",
				},
			},
			wantErr: false,
		},
		{
			name: "valid-multiple-mixed",
			creds: []*targets.SessionCredential{
				{
					CredentialSource: &targets.CredentialSource{
						CredentialType: string(credential.UsernamePasswordType),
					},
					Credential: map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
				{
					CredentialSource: &targets.CredentialSource{
						Type: "vault",
					},
					Secret: &targets.SessionSecret{
						Decoded: map[string]interface{}{
							"username": "user1",
							"password": "pass1",
						},
					},
				},
				{
					CredentialSource: &targets.CredentialSource{
						Type: "static",
					},
					Secret: &targets.SessionSecret{
						Decoded: map[string]interface{}{
							"username": "user2",
							"password": "pass2",
						},
					},
				},
			},
			wantCreds: []usernamePasswordCredentials{
				{
					Username: "user",
					Password: "pass",
				},
				{
					Username: "user1",
					Password: "pass1",
				},
				{
					Username: "user2",
					Password: "pass2",
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
				assert.Nil(creds)
				return
			}
			require.NoError(err)
			assert.ElementsMatch(tt.wantCreds, creds)
		})
	}
}
