// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package oidc

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestPrompts_Create(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))

	type args struct {
		authMethodId string
		prompt       PromptParam
	}
	tests := []struct {
		name            string
		args            args
		want            *Prompt
		wantErr         bool
		wantIsErr       errors.Code
		create          bool
		wantCreateErr   bool
		wantCreateIsErr errors.Code
	}{
		{
			name: "valid",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				prompt:       SelectAccount,
			},
			create: true,
			want: func() *Prompt {
				want := AllocPrompt()
				want.OidcMethodId = testAuthMethod.PublicId
				want.PromptParam = string(SelectAccount)
				return &want
			}(),
		},
		{
			name: "dup", // must follow "valid" test. Prompt must be be unique for an OidcMethodId
			args: args{
				authMethodId: testAuthMethod.PublicId,
				prompt:       SelectAccount,
			},
			create: true,
			want: func() *Prompt {
				want := AllocPrompt()
				want.OidcMethodId = testAuthMethod.PublicId
				want.PromptParam = string(SelectAccount)
				return &want
			}(),
			wantCreateErr:   true,
			wantCreateIsErr: errors.NotUnique,
		},
		{
			name: "empty-auth-method",
			args: args{
				authMethodId: "",
				prompt:       Consent,
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "empty-prompt",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				prompt:       "",
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
		{
			name: "supported-prompt",
			args: args{
				authMethodId: testAuthMethod.PublicId,
				prompt:       PromptParam("EVE256"), // The unsupported evesdropper 256 curve
			},
			wantErr:   true,
			wantIsErr: errors.InvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := NewPrompt(ctx, tt.args.authMethodId, tt.args.prompt)
			if tt.wantErr {
				require.Error(err)
				assert.True(errors.Match(errors.T(tt.wantIsErr), err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
			if tt.create {
				ctx := context.Background()
				err = rw.Create(ctx, got)
				if tt.wantCreateErr {
					assert.Error(err)
					assert.True(errors.Match(errors.T(tt.wantCreateIsErr), err))
					return
				} else {
					assert.NoError(err)
				}
				found := AllocPrompt()
				require.NoError(rw.LookupWhere(ctx, &found, "oidc_method_id = ? and prompt = ?", []any{tt.args.authMethodId, string(tt.args.prompt)}))
				assert.Equal(got, &found)
			}
		})
	}
}

func TestPrompt_Delete(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)
	org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	rw := db.New(conn)

	databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
	require.NoError(t, err)

	testAuthMethod := TestAuthMethod(
		t,
		conn,
		databaseWrapper,
		org.PublicId,
		InactiveState,
		"alice_rp",
		"my-dogs-name",
		WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]),
		WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]),
		WithPrompts(Consent))

	testResource := func(authMethodId string, prompt PromptParam) *Prompt {
		c, err := NewPrompt(ctx, authMethodId, prompt)
		require.NoError(t, err)
		return c
	}
	tests := []struct {
		name            string
		Prompt          *Prompt
		wantRowsDeleted int
		overrides       func(*Prompt)
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name:            "valid",
			Prompt:          testResource(testAuthMethod.PublicId, SelectAccount),
			wantErr:         false,
			wantRowsDeleted: 1,
		},
		{
			name:            "bad-OidcMethodId",
			Prompt:          testResource(testAuthMethod.PublicId, Login),
			overrides:       func(c *Prompt) { c.OidcMethodId = "bad-id" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
		{
			name:            "bad-prompt",
			Prompt:          testResource(testAuthMethod.PublicId, None),
			overrides:       func(c *Prompt) { c.PromptParam = "bad-prompt" },
			wantErr:         false,
			wantRowsDeleted: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			ctx := context.Background()
			cp := tt.Prompt.Clone()
			require.NoError(rw.Create(ctx, &cp))

			if tt.overrides != nil {
				tt.overrides(cp)
			}
			deletedRows, err := rw.Delete(ctx, &cp)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			if tt.wantRowsDeleted == 0 {
				assert.Equal(tt.wantRowsDeleted, deletedRows)
				return
			}
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			found := AllocPrompt()
			err = rw.LookupWhere(ctx, &found, "oidc_method_id = ? and prompt = ?", []any{tt.Prompt.OidcMethodId, tt.Prompt.String()})
			assert.Truef(errors.IsNotFoundError(err), "unexpected error: %s", err.Error())
		})
	}
}

func TestPrompt_Clone(t *testing.T) {
	t.Parallel()
	ctx := context.TODO()
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kmsCache := kms.TestKms(t, conn, wrapper)

	t.Run("valid", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewPrompt(ctx, m.PublicId, Consent)
		require.NoError(err)
		cp := orig.Clone()
		assert.True(proto.Equal(cp.Prompt, orig.Prompt))
	})
	t.Run("not-equal", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		org, _ := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
		databaseWrapper, err := kmsCache.GetWrapper(context.Background(), org.PublicId, kms.KeyPurposeDatabase)
		require.NoError(err)
		m := TestAuthMethod(t, conn, databaseWrapper, org.PublicId, InactiveState, "alice_rp", "my-dogs-name",
			WithIssuer(TestConvertToUrls(t, "https://alice.com")[0]), WithApiUrl(TestConvertToUrls(t, "https://api.com")[0]))
		orig, err := NewPrompt(ctx, m.PublicId, Consent)
		require.NoError(err)
		orig2, err := NewPrompt(ctx, m.PublicId, SelectAccount)
		require.NoError(err)

		cp := orig.Clone()
		assert.True(!proto.Equal(cp.Prompt, orig2.Prompt))
	})
}

func TestPrompt_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := defaultPromptTableName
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := AllocPrompt()
			require.Equal(defaultTableName, def.TableName())
			m := AllocPrompt()
			m.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, m.TableName())
		})
	}
}

func TestPrompt_SupportedPrompt(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		prompt PromptParam
		want   bool
	}{
		{
			name:   "none-prompt",
			prompt: None,
			want:   true,
		},
		{
			name:   "login-prompt",
			prompt: Login,
			want:   true,
		},
		{
			name:   "consent-prompt",
			prompt: Consent,
			want:   true,
		},
		{
			name:   "select-account-prompt",
			prompt: SelectAccount,
			want:   true,
		},
		{
			name:   "invalid-prompt",
			prompt: "invalid",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got := SupportedPrompt(tt.prompt)
			assert.Equal(tt.want, got)
		})
	}
}
