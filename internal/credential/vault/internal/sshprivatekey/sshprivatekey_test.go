// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package sshprivatekey

import (
	"testing"

	"github.com/hashicorp/boundary/internal/credential"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/ssh/testdata"
)

func TestExtract(t *testing.T) {
	t.Parallel()

	edKey := testdata.PEMBytes["ed25519"]
	rsaKey := testdata.PEMBytes["rsa"]

	type args struct {
		s      data
		uAttr  string
		pkAttr string
		pAttr  string
	}
	type sshpk struct {
		user       string
		privateKey credential.PrivateKey
		passphrase []byte
	}
	tests := []struct {
		name  string
		given args
		want  sshpk
	}{
		{
			name: "nil-input",
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name:  "no-input",
			given: args{},
			want:  sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "no-secret",
			given: args{
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "no-match-username-secret",
			given: args{
				s: data{
					"username-wrong": "user",
					"private_key":    string(edKey),
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "no-match-private-key-secret",
			given: args{
				s: data{
					"username":          "user",
					"private_key-wrong": string(edKey),
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "valid-default",
			given: args{
				s: data{
					"username":    "user",
					"private_key": string(edKey),
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "user", privateKey: edKey, passphrase: nil},
		},
		{
			name: "valid-default-with-passphrase",
			given: args{
				s: data{
					"username":    "user",
					"private_key": string(edKey),
					"passphrase":  "my-pass",
				},
				uAttr:  "username",
				pkAttr: "private_key",
				pAttr:  "passphrase",
			},
			want: sshpk{user: "user", privateKey: edKey, passphrase: []byte("my-pass")},
		},
		{
			name: "no-match-username-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username-wrong": "user",
						"private_key":    string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "no-match-private-key-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":          "user",
						"private_key-wrong": string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "valid-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "user", privateKey: edKey, passphrase: nil},
		},
		{
			name: "valid-kv2-with-passphrase",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":    "user",
						"private_key": string(edKey),
						"passphrase":  "my-pass",
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
				pAttr:  "passphrase",
			},
			want: sshpk{user: "user", privateKey: edKey, passphrase: []byte("my-pass")},
		},
		{
			name: "no-metadata-kv2",
			given: args{
				s: data{
					"data": map[string]any{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "invalid-metadata-kv2",
			given: args{
				s: data{
					"metadata": "string",
					"data": map[string]any{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "invalid-field-kv2",
			given: args{
				s: data{
					"invalid":  map[string]any{},
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil, passphrase: nil},
		},
		{
			name: "valid-order-default-first",
			given: args{
				s: data{
					"username":    "default-user",
					"private_key": string(rsaKey),
					"metadata":    map[string]any{},
					"data": map[string]any{
						"username":    "kv2-user",
						"private_key": string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "private_key",
			},
			want: sshpk{user: "default-user", privateKey: rsaKey, passphrase: nil},
		},
		{
			name: "default-user-json-pointer-pk",
			given: args{
				s: data{
					"username": "default-user",
					"testing": map[string]any{
						"private_key": string(edKey),
					},
				},
				uAttr:  "username",
				pkAttr: "/testing/private_key",
			},
			want: sshpk{user: "default-user", privateKey: edKey, passphrase: nil},
		},
		{
			name: "default-pk-json-pointer-user",
			given: args{
				s: data{
					"private_key": string(edKey),
					"testing": map[string]any{
						"special": "not-so-special",
					},
				},
				uAttr:  "/testing/special",
				pkAttr: "private_key",
			},
			want: sshpk{user: "not-so-special", privateKey: edKey, passphrase: nil},
		},
		{
			name: "all-json-pointer",
			given: args{
				s: data{
					"first-path": map[string]any{
						"deeper-path": map[string]any{
							"my-special-user": "you-found-me",
						},
					},
					"testing": map[string]any{
						"private_key": string(edKey),
					},
					"hidden": map[string]any{
						"pass": "my-pass",
					},
				},
				uAttr:  "/first-path/deeper-path/my-special-user",
				pkAttr: "/testing/private_key",
				pAttr:  "/hidden/pass",
			},
			want: sshpk{user: "you-found-me", privateKey: edKey, passphrase: []byte("my-pass")},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			user, privateKey, passphrase := Extract(tt.given.s, tt.given.uAttr, tt.given.pkAttr, tt.given.pAttr)
			assert.Equal(tt.want.user, user)
			assert.Equal(tt.want.privateKey, privateKey)
			assert.Equal(tt.want.passphrase, passphrase)
		})
	}
}
