package userpassword

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseToUsrPass(t *testing.T) {
	t.Parallel()

	type args struct {
		s     data
		uAttr string
		pAttr string
	}
	type usrPass struct {
		user string
		pass string
	}
	tests := []struct {
		name  string
		given args
		want  usrPass
	}{
		{
			name: "nil-input",
			want: usrPass{user: "", pass: ""},
		},
		{
			name:  "no-input",
			given: args{},
			want:  usrPass{user: "", pass: ""},
		},
		{
			name: "no-secret",
			given: args{
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "no-match-username-secret",
			given: args{
				s: data{
					"username-wrong": "user",
					"password":       "pass",
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "no-match-username-secret",
			given: args{
				s: data{
					"username":       "user",
					"password-wrong": "pass",
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "valid-default",
			given: args{
				s: data{
					"username": "user",
					"password": "pass",
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "user", pass: "pass"},
		},
		{
			name: "no-match-username-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username-wrong": "user",
						"password":       "pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "no-match-password-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username":       "user",
						"password-wrong": "pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "valid-kv2",
			given: args{
				s: data{
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "user", pass: "pass"},
		},
		{
			name: "no-metadata-kv2",
			given: args{
				s: data{
					"data": map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "invalid-metadata-kv2",
			given: args{
				s: data{
					"metadata": "string",
					"data": map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "invalid-field-kv2",
			given: args{
				s: data{
					"invalid":  map[string]interface{}{},
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username": "user",
						"password": "pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "", pass: ""},
		},
		{
			name: "valid-order-default-first",
			given: args{
				s: data{
					"username": "default-user",
					"password": "default-pass",
					"metadata": map[string]interface{}{},
					"data": map[string]interface{}{
						"username": "kv2-user",
						"password": "kv2-pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "default-user", pass: "default-pass"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			user, pass := Extract(tt.given.s, tt.given.uAttr, tt.given.pAttr)
			assert.Equal(tt.want.user, user)
			assert.Equal(tt.want.pass, pass)
		})
	}
}
