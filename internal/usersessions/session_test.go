package usersessions

import (
	"context"
	"testing"

	"github.com/hashicorp/vault/sdk/helper/base62"
	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/usersessions/store"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestSession_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

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
		want    *Session
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
			want: &Session{
				Session: &store.Session{
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
			got, err := NewSession(tt.args.scopeId, tt.args.userId, tt.args.authMethodId, tt.args.opts...)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(got)
			} else {
				assert.NoError(err)
				if assert.NotNil(got) {
					assert.Emptyf(got.PublicId, "PublicId set")
					assert.Equal(tt.want, got)

					id, err := newSessionId()
					assert.NoError(err)
					tt.want.PublicId = id
					got.PublicId = id

					token, err := newSessionToken()
					assert.NoError(err)
					tt.want.Token = token
					got.Token = token

					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}

func TestSession_Update(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	})

	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId := setupAuthMethod(t, conn, org.GetPublicId())

	newSessId, err := newSessionId()
	require.NoError(err)

	type args struct {
		fieldMask []string
		nullMask  []string
		session   *store.Session
	}

	var tests = []struct {
		name    string
		args    args
		want    *Session
		cnt     int
		wantErr bool
	}{
		{
			name: "immutable-userid",
			args: args{
				fieldMask: []string{"IamUserId"},
				session:   &store.Session{IamUserId: u.GetPublicId()},
			},
			wantErr: true,
		},
		{
			name: "immutable-authmethodid",
			args: args{
				fieldMask: []string{"AuthMethodId"},
				session:   &store.Session{AuthMethodId: amId},
			},
			wantErr: true,
		},
		{
			name: "immutable-scopeid",
			args: args{
				fieldMask: []string{"IamScopeId"},
				session:   &store.Session{ScopeId: u.GetScopeId()},
			},
			wantErr: true,
		},
		{
			name: "immutable-publicid",
			args: args{
				fieldMask: []string{"PublicId"},
				session:   &store.Session{PublicId: newSessId},
			},
			wantErr: true,
		},
		{
			name: "update-last-access-time",
			args: args{
				nullMask: []string{"LastAccessTime"},
				session:  &store.Session{},
			},
			cnt: 1,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			w := db.New(conn)

			sess := testSession(t, conn)
			proto.Merge(sess.Session, tt.args.session)

			cnt, err := w.Update(context.Background(), sess, tt.args.fieldMask, tt.args.nullMask)
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

func testSession(t *testing.T, conn *gorm.DB) *Session {
	t.Helper()
	assert := assert.New(t)
	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	amId := setupAuthMethod(t, conn, org.GetPublicId())
	sess, err := NewSession(org.GetPublicId(), u.GetPublicId(), amId)
	assert.NoError(err)
	assert.NotNil(sess)
	id, err := newSessionId()
	assert.NoError(err)
	assert.NotEmpty(id)
	sess.PublicId = id

	token, err := newSessionToken()
	assert.NoError(err)
	assert.NotEmpty(token)
	sess.Token = token

	w := db.New(conn)
	err2 := w.Create(context.Background(), sess)
	assert.NoError(err2)
	return sess
}

// Returns auth method id
// TODO: Remove this when the auth method repos are created with the relevant test methods.
func setupAuthMethod(t *testing.T, conn *gorm.DB, scope string) string {
	t.Helper()
	require := require.New(t)
	insert := `insert into auth_method
	(public_id, scope_id)
	values
	($1, $2);`
	amId, err := authMethodId()
	require.NoError(err)
	db := conn.DB()
	_, err = db.Query(insert, amId, scope)
	require.NoError(err)
	return amId
}

func authMethodId() (string, error) {
	id, err := base62.Random(10)
	if err != nil {
		return "", err
	}
	return "am_" + id, nil
}
