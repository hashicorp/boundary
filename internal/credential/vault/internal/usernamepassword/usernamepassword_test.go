// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package usernamepassword

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
			name: "no-match-password-secret",
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
					"metadata": map[string]any{},
					"data": map[string]any{
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
					"metadata": map[string]any{},
					"data": map[string]any{
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
					"metadata": map[string]any{},
					"data": map[string]any{
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
					"data": map[string]any{
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
					"data": map[string]any{
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
					"invalid":  map[string]any{},
					"metadata": map[string]any{},
					"data": map[string]any{
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
					"metadata": map[string]any{},
					"data": map[string]any{
						"username": "kv2-user",
						"password": "kv2-pass",
					},
				},
				uAttr: "username",
				pAttr: "password",
			},
			want: usrPass{user: "default-user", pass: "default-pass"},
		},
		{
			name: "default-user-json-pointer-password",
			given: args{
				s: data{
					"username": "default-user",
					"testing": map[string]any{
						"my-password": "secret",
					},
				},
				uAttr: "username",
				pAttr: "/testing/my-password",
			},
			want: usrPass{user: "default-user", pass: "secret"},
		},
		{
			name: "default-pk-json-pointer-user",
			given: args{
				s: data{
					"password": "default-pass",
					"testing": map[string]any{
						"a-user-name": "me",
					},
				},
				uAttr: "/testing/a-user-name",
				pAttr: "password",
			},
			want: usrPass{user: "me", pass: "default-pass"},
		},
		{
			name: "both-json-pointer",
			given: args{
				s: data{
					"first-path": map[string]any{
						"deeper-path": map[string]any{
							"my-special-user": "you-found-me",
						},
					},
					"testing": map[string]any{
						"password": "secret",
					},
				},
				uAttr: "/first-path/deeper-path/my-special-user",
				pAttr: "/testing/password",
			},
			want: usrPass{user: "you-found-me", pass: "secret"},
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
