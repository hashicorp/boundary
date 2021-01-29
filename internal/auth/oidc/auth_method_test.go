package oidc

import (
	"context"
	"net/url"
	"reflect"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc/store"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthMethod_Create(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	type args struct {
		scopeId      string
		state        AuthMethodState
		discoveryURL *url.URL
		clientId     string
		clientSecret ClientSecret
		maxAge       uint32
		opt          []Option
	}
	tests := []struct {
		name          string
		args          args
		want          *AuthMethod
		wantErr       bool
		wantIsErr     errors.Code
		create        bool
		wantCreateErr bool
	}{
		{
			name: "valid",
			args: args{
				scopeId:      org.PublicId,
				state:        InactiveState,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				maxAge:       0,
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			want: func() *AuthMethod {
				a := allocAuthMethod()
				a.ScopeId = org.PublicId
				a.State = string(InactiveState)
				a.DiscoveryUrl = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = 0
				a.Name = "alice.com"
				a.Description = "alice's restaurant rp"
				return &a
			}(),
		},
		{
			name: "valid-with-no-options",
			args: args{
				scopeId:      org.PublicId,
				state:        InactiveState,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				maxAge:       1000,
			},
			want: func() *AuthMethod {
				a := allocAuthMethod()
				a.ScopeId = org.PublicId
				a.State = string(InactiveState)
				a.DiscoveryUrl = "http://alice.com"
				a.ClientId = "alice_rp"
				a.ClientSecret = "rp-secret"
				a.MaxAge = 1000
				return &a
			}(),
		},
		{
			name: "empty-scope-id",
			args: args{
				scopeId:      "",
				state:        InactiveState,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				maxAge:       0,
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "unknown-state-id",
			args: args{
				scopeId:      org.PublicId,
				state:        UnknownState,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				maxAge:       0,
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "bad-state-id",
			args: args{
				scopeId:      org.PublicId,
				state:        AuthMethodState("bad-state"),
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				maxAge:       0,
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "nil-url",
			args: args{
				scopeId:      org.PublicId,
				state:        InactiveState,
				discoveryURL: nil,
				clientId:     "alice_rp",
				clientSecret: ClientSecret("rp-secret"),
				maxAge:       0,
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "missing-client-id",
			args: args{
				scopeId:      org.PublicId,
				state:        InactiveState,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "",
				clientSecret: ClientSecret("rp-secret"),
				maxAge:       0,
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "missing-client-secret",
			args: args{
				scopeId:      org.PublicId,
				state:        InactiveState,
				discoveryURL: func() *url.URL { u, err := url.Parse("http://alice.com"); require.NoError(t, err); return u }(),
				clientId:     "alice_rp",
				clientSecret: ClientSecret(""),
				maxAge:       0,
				opt:          []Option{WithDescription("alice's restaurant rp"), WithName("alice.com")},
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewAuthMethod(tt.args.scopeId, tt.args.state, tt.args.discoveryURL, tt.args.clientId, tt.args.clientSecret, tt.args.maxAge, tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				id, err := newAuthMethodId()
				require.NoError(err)
				got.PublicId = id
				err = db.New(conn).Create(context.Background(), got)
				if tt.wantCreateErr {
					assert.Error(err)
					return
				} else {
					assert.NoError(err)
				}
			}
		})
	}
}

func TestAuthMethod_clone(t *testing.T) {
	type fields struct {
		AuthMethod *store.AuthMethod
		tableName  string
	}
	tests := []struct {
		name   string
		fields fields
		want   *AuthMethod
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := &AuthMethod{
				AuthMethod: tt.fields.AuthMethod,
				tableName:  tt.fields.tableName,
			}
			if got := a.clone(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("AuthMethod.clone() = %v, want %v", got, tt.want)
			}
		})
	}
}
