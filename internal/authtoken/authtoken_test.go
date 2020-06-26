package authtoken

// This file contains tests for methods defined in authtoken.go as well as tests which exercise the db
// functionality directly without going through the respository.  Repository centric tests should be
// placed in repository_test.go

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/authtoken/store"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAuthToken_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId1 := setupAuthMethod(t, conn, org.GetPublicId())

	type args struct {
		scopeId      string
		userId       string
		authMethodId string
		opts         []Option
	}

	var tests = []struct {
		name    string
		args    args
		want    *AuthToken
		wantErr bool
	}{
		{
			name: "blank-scopeId",
			args: args{
				userId:       u.GetPublicId(),
				authMethodId: amId1,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "blank-userId",
			args: args{
				scopeId:      org.GetPublicId(),
				authMethodId: amId1,
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "blank-authMethodId",
			args: args{
				scopeId: org.GetPublicId(),
				userId:  u.GetPublicId(),
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				scopeId:      org.GetPublicId(),
				userId:       u.GetPublicId(),
				authMethodId: amId1,
			},
			want: &AuthToken{
				AuthToken: &store.AuthToken{
					ScopeId:      org.GetPublicId(),
					IamUserId:    u.GetPublicId(),
					AuthMethodId: amId1,
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewAuthToken(tt.args.scopeId, tt.args.userId, tt.args.authMethodId, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					assert.Emptyf(got.PublicId, "PublicId set")
					assert.Equal(tt.want, got)

					id, err := newAuthTokenId()
					assert.NoError(err)
					tt.want.PublicId = id
					got.PublicId = id

					token, err := newAuthToken()
					assert.NoError(err)
					tt.want.Token = token
					got.Token = token
					err = got.EncryptData(context.Background(), wrapper)
					require.NoError(t, err)

					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}

func TestAuthToken_DbUpdate(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId := setupAuthMethod(t, conn, org.GetPublicId())

	newAuthTokId, err := newAuthTokenId()
	require.NoError(t, err)

	type args struct {
		fieldMask []string
		nullMask  []string
		authTok   *store.AuthToken
	}

	var tests = []struct {
		name    string
		args    args
		want    *AuthToken
		cnt     int
		wantErr bool
	}{
		{
			name: "immutable-userid",
			args: args{
				fieldMask: []string{"IamUserId"},
				authTok:   &store.AuthToken{IamUserId: u.GetPublicId()},
			},
			wantErr: true,
		},
		{
			name: "immutable-authmethodid",
			args: args{
				fieldMask: []string{"AuthMethodId"},
				authTok:   &store.AuthToken{AuthMethodId: amId},
			},
			wantErr: true,
		},
		{
			name: "immutable-scopeid",
			args: args{
				fieldMask: []string{"IamScopeId"},
				authTok:   &store.AuthToken{ScopeId: u.GetScopeId()},
			},
			wantErr: true,
		},
		{
			name: "immutable-publicid",
			args: args{
				fieldMask: []string{"PublicId"},
				authTok:   &store.AuthToken{PublicId: newAuthTokId},
			},
			wantErr: true,
		},
		{
			name: "update-last-access-time",
			args: args{
				nullMask: []string{"ApproximateLastAccessTime"},
				authTok:  &store.AuthToken{},
			},
			cnt: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			w := db.New(conn)

			authTok := testAuthToken(t, conn)
			proto.Merge(authTok.AuthToken, tt.args.authTok)

			err := authTok.EncryptData(context.Background(), wrapper)
			require.NoError(t, err)
			cnt, err := w.Update(context.Background(), authTok, tt.args.fieldMask, tt.args.nullMask)
			if tt.wantErr {
				t.Logf("Got error :%v", err)
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
			assert.Equal(tt.cnt, cnt)
		})
	}
}

func TestAuthToken_DbCreate(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	wrapper := db.TestWrapper(t)

	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId := setupAuthMethod(t, conn, org.GetPublicId())
	org2, _ := iam.TestScopes(t, conn)
	u2 := iam.TestUser(t, conn, org2.GetPublicId())
	amId2 := setupAuthMethod(t, conn, org2.GetPublicId())
	createdAuthToken := testAuthToken(t, conn)

	testAuthTokenId := func() string {
		id, err := newAuthTokenId()
		require.NoError(t, err)
		return id
	}

	var tests = []struct {
		name      string
		in        *store.AuthToken
		wantError bool
	}{
		{
			name: "basic",
			in: &store.AuthToken{
				PublicId:     testAuthTokenId(),
				Token:        "anything",
				ScopeId:      org.GetPublicId(),
				IamUserId:    u.GetPublicId(),
				AuthMethodId: amId,
			},
		},
		{
			name: "duplicate-id",
			in: &store.AuthToken{
				PublicId:     createdAuthToken.GetPublicId(),
				Token:        "duplicateid_test",
				ScopeId:      org.GetPublicId(),
				IamUserId:    u.GetPublicId(),
				AuthMethodId: amId,
			},
			wantError: true,
		},
		{
			name: "mismatch-user-scope",
			in: &store.AuthToken{
				PublicId:     testAuthTokenId(),
				Token:        "mismatch-user-scope",
				ScopeId:      org.GetPublicId(),
				IamUserId:    u2.GetPublicId(),
				AuthMethodId: amId,
			},
			wantError: true,
		},
		{
			name: "mismatch-authmethod-scope",
			in: &store.AuthToken{
				PublicId:     testAuthTokenId(),
				Token:        "mismatch-authmethod-scope",
				ScopeId:      org.GetPublicId(),
				IamUserId:    u.GetPublicId(),
				AuthMethodId: amId2,
			},
			wantError: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			at := &AuthToken{AuthToken: tt.in}
			err := at.EncryptData(context.Background(), wrapper)
			require.NoError(t, err)
			err = db.New(conn).Create(context.Background(), at)
			if tt.wantError {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}

func TestAuthToken_DbDelete(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	testAuthTokenId := func() string {
		id, err := newAuthTokenId()
		require.NoError(t, err)
		return id
	}

	existingAuthTok := testAuthToken(t, conn)

	var tests = []struct {
		name      string
		at        *AuthToken
		wantError bool
		wantCnt   int
	}{
		{
			name:    "basic",
			at:      &AuthToken{AuthToken: &store.AuthToken{PublicId: existingAuthTok.GetPublicId()}},
			wantCnt: 1,
		},
		{
			name:    "delete-nothing",
			at:      &AuthToken{AuthToken: &store.AuthToken{PublicId: testAuthTokenId()}},
			wantCnt: 0,
		},
		{
			name:      "delete-nil",
			at:        nil,
			wantCnt:   0,
			wantError: true,
		},
		{
			name:      "delete-no-public-id",
			at:        &AuthToken{AuthToken: &store.AuthToken{}},
			wantCnt:   0,
			wantError: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			cnt, err := db.New(conn).Delete(context.Background(), tt.at)
			assert.Equal(tt.wantCnt, cnt)
			if tt.wantError {
				assert.Error(err)
			} else {
				assert.NoError(err)
			}
		})
	}
}
