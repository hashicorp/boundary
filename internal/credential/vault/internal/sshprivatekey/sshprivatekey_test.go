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
		s     data
		uAttr string
		pAttr string
	}
	type sshpk struct {
		user       string
		privateKey credential.PrivateKey
	}
	tests := []struct {
		name  string
		given args
		want  sshpk
	}{
		{
			name: "nil-input",
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name:  "no-input",
			given: args{},
			want:  sshpk{user: "", privateKey: nil},
		},
		{
			name: "no-secret",
			given: args{
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "no-match-username-secret",
			given: args{
				s: data{
					"username-wrong": "user",
					"private_key":    string(edKey),
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "no-match-private-key-secret",
			given: args{
				s: data{
					"username":          "user",
					"private_key-wrong": string(edKey),
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "valid-default",
			given: args{
				s: data{
					"username":    "user",
					"private_key": string(edKey),
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "user", privateKey: edKey},
		},
		{
			name: "valid-default-private-key-string",
			given: args{
				s: data{
					"username":    "user",
					"private_key": string(edKey),
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "user", privateKey: edKey},
		},
		{
			name: "no-match-username-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username-wrong": "user",
						"private_key":    string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "no-match-private-key-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":          "user",
						"private_key-wrong": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "valid-kv2",
			given: args{
				s: data{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "user", privateKey: edKey},
		},
		{
			name: "valid-kv2-private-key-string",
			given: args{
				s: data{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "user", privateKey: edKey},
		},
		{
			name: "no-metadata-kv2",
			given: args{
				s: data{
					"data": map[string]interface{}{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "invalid-metadata-kv2",
			given: args{
				s: data{
					"metadata": "string",
					"data": map[string]interface{}{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "invalid-field-kv2",
			given: args{
				s: data{
					"invalid":  map[string]interface{}{},
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":    "user",
						"private_key": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "", privateKey: nil},
		},
		{
			name: "valid-order-default-first",
			given: args{
				s: data{
					"username":    "default-user",
					"private_key": string(rsaKey),
					"metadata":    map[string]interface{}{},
					"data": map[string]interface{}{
						"username":    "kv2-user",
						"private_key": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "private_key",
			},
			want: sshpk{user: "default-user", privateKey: rsaKey},
		},
		{
			name: "default-user-json-pointer-pk",
			given: args{
				s: data{
					"username": "default-user",
					"testing": map[string]interface{}{
						"private_key": string(edKey),
					},
				},
				uAttr: "username",
				pAttr: "/testing/private_key",
			},
			want: sshpk{user: "default-user", privateKey: edKey},
		},
		{
			name: "default-pk-json-pointer-user",
			given: args{
				s: data{
					"private_key": string(edKey),
					"testing": map[string]interface{}{
						"special": "not-so-special",
					},
				},
				uAttr: "/testing/special",
				pAttr: "private_key",
			},
			want: sshpk{user: "not-so-special", privateKey: edKey},
		},
		{
			name: "both-json-pointer",
			given: args{
				s: data{
					"first-path": map[string]interface{}{
						"deeper-path": map[string]interface{}{
							"my-special-user": "you-found-me",
						},
					},
					"testing": map[string]interface{}{
						"private_key": string(edKey),
					},
				},
				uAttr: "/first-path/deeper-path/my-special-user",
				pAttr: "/testing/private_key",
			},
			want: sshpk{user: "you-found-me", privateKey: edKey},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			user, privateKey := Extract(tt.given.s, tt.given.uAttr, tt.given.pAttr)
			assert.Equal(tt.want.user, user)
			assert.Equal(tt.want.privateKey, privateKey)
		})
	}
}
