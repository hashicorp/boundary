// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package password

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBaseToPass(t *testing.T) {
	t.Parallel()

	type args struct {
		s     data
		pAttr string
	}
	type pass struct {
		pass string
	}
	tests := []struct {
		name  string
		given args
		want  pass
	}{
		{
			name: "nil-input",
			want: pass{pass: ""},
		},
		{
			name:  "no-input",
			given: args{},
			want:  pass{pass: ""},
		},
		{
			name: "no-secret",
			given: args{
				pAttr: "password",
			},
			want: pass{pass: ""},
		},
		{
			name: "no-match-password-secret",
			given: args{
				s: data{
					"password-wrong": "pass",
				},
				pAttr: "password",
			},
			want: pass{pass: ""},
		},
		{
			name: "valid-default",
			given: args{
				s: data{
					"password": "pass",
				},
				pAttr: "password",
			},
			want: pass{pass: "pass"},
		},
		{
			name: "no-match-password-secret-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"password-wrong": "pass",
					},
				},
				pAttr: "password",
			},
			want: pass{pass: ""},
		},
		{
			name: "valid-kv2",
			given: args{
				s: data{
					"metadata": map[string]any{},
					"data": map[string]any{
						"password": "pass",
					},
				},
				pAttr: "password",
			},
			want: pass{pass: "pass"},
		},
		{
			name: "no-metadata-kv2",
			given: args{
				s: data{
					"data": map[string]any{
						"password": "pass",
					},
				},
				pAttr: "password",
			},
			want: pass{pass: ""},
		},
		{
			name: "invalid-metadata-kv2",
			given: args{
				s: data{
					"metadata": "string",
					"data": map[string]any{
						"password": "pass",
					},
				},
				pAttr: "password",
			},
			want: pass{pass: ""},
		},
		{
			name: "invalid-field-kv2",
			given: args{
				s: data{
					"invalid":  map[string]any{},
					"metadata": map[string]any{},
					"data": map[string]any{
						"password": "pass",
					},
				},
				pAttr: "password",
			},
			want: pass{pass: ""},
		},
		{
			name: "valid-order-default-first",
			given: args{
				s: data{
					"password": "default-pass",
					"metadata": map[string]any{},
					"data": map[string]any{
						"password": "kv2-pass",
					},
				},
				pAttr: "password",
			},
			want: pass{pass: "default-pass"},
		},
		{
			name: "json-pointer-password",
			given: args{
				s: data{
					"testing": map[string]any{
						"my-password": "secret",
					},
				},
				pAttr: "/testing/my-password",
			},
			want: pass{pass: "secret"},
		},
		{
			name: "deep-json-pointer",
			given: args{
				s: data{
					"first-path": map[string]any{
						"deeper-path": map[string]any{
							"my-password": "deeper-secret",
						},
					},
				},
				pAttr: "/first-path/deeper-path/my-password",
			},
			want: pass{pass: "deeper-secret"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			pass := Extract(tt.given.s, tt.given.pAttr)
			assert.Equal(tt.want.pass, pass)
		})
	}
}
