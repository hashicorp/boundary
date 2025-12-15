// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package usernamepassworddomain

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseToUsrPassDomain(t *testing.T) {
	t.Parallel()

	type args struct {
		s     data
		uAttr string
		pAttr string
		dAttr string
	}
	type usrPassDomain struct {
		user   string
		pass   string
		domain string
	}
	tests := []struct {
		name  string
		given args
		want  usrPassDomain
	}{
		{
			name: "nil-input",
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name:  "no-input",
			given: args{},
			want:  usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "no-secret",
			given: args{
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "no-match-username-secret",
			given: args{
				s: data{
					"username-wrong": "user",
					"password":       "pass",
					"domain":         "domain",
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "no-match-password-secret",
			given: args{
				s: data{
					"username":       "user",
					"password-wrong": "pass",
					"domain":         "domain",
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "no-match-domain-secret",
			given: args{
				s: data{
					"username":     "user",
					"password":     "pass",
					"domain-wrong": "domain",
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "valid-default",
			given: args{
				s: data{
					"username": "user",
					"password": "pass",
					"domain":   "domain",
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "user", pass: "pass", domain: "domain"},
		},
		{
			name: "no-match-username-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username-wrong": "user",
						"password":       "pass",
						"domain":         "domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "no-match-password-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":       "user",
						"password-wrong": "pass",
						"domain":         "domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "no-match-domain-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username":     "user",
						"password":     "pass",
						"domain-wrong": "domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "valid-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"username": "user",
						"password": "pass",
						"domain":   "domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "user", pass: "pass", domain: "domain"},
		},
		{
			name: "no-metadata-kv2",
			given: args{
				s: data{
					"data": map[string]any{
						"username": "user",
						"password": "pass",
						"domain":   "domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "invalid-metadata-kv2",
			given: args{
				s: data{
					"metadata": "string",
					"data": map[string]any{
						"username": "user",
						"password": "pass",
						"domain":   "domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
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
						"domain":   "domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "", pass: "", domain: ""},
		},
		{
			name: "valid-order-default-first",
			given: args{
				s: data{
					"username": "default-user",
					"password": "default-pass",
					"domain":   "default-domain",
					"metadata": map[string]any{},
					"data": map[string]any{
						"username": "kv2-user",
						"password": "kv2-pass",
						"domain":   "kv2-domain",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "default-user", pass: "default-pass", domain: "default-domain"},
		},
		{
			name: "default-user-json-pointer-password",
			given: args{
				s: data{
					"username": "default-user",
					"domain":   "default-domain",
					"testing": map[string]any{
						"my-password": "secret",
					},
				},
				uAttr: "username",
				pAttr: "/testing/my-password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "default-user", pass: "secret", domain: "default-domain"},
		},
		{
			name: "default-pk-json-pointer-user",
			given: args{
				s: data{
					"password": "default-pass",
					"domain":   "default-domain",
					"testing": map[string]any{
						"a-user-name": "me",
					},
				},
				uAttr: "/testing/a-user-name",
				pAttr: "password",
				dAttr: "domain",
			},
			want: usrPassDomain{user: "me", pass: "default-pass", domain: "default-domain"},
		},
		{
			name: "default-dm-json-pointer-user",
			given: args{
				s: data{
					"username": "default-user",
					"password": "default-pass",
					"domain-site": map[string]any{
						"a-domain": "domain.com",
					},
				},
				uAttr: "username",
				pAttr: "password",
				dAttr: "/domain-site/a-domain",
			},
			want: usrPassDomain{user: "default-user", pass: "default-pass", domain: "domain.com"},
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
						"password": "secret",
					},
					"domain-site": map[string]any{
						"a-domain": "domain.com",
					},
				},
				uAttr: "/first-path/deeper-path/my-special-user",
				pAttr: "/testing/password",
				dAttr: "/domain-site/a-domain",
			},
			want: usrPassDomain{user: "you-found-me", pass: "secret", domain: "domain.com"},
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			user, pass, domain := Extract(tt.given.s, tt.given.uAttr, tt.given.pAttr, tt.given.dAttr)
			assert.Equal(tt.want.user, user)
			assert.Equal(tt.want.pass, pass)
			assert.Equal(tt.want.domain, domain)
		})
	}
}
