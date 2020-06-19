package usersessions

import (
	"context"
	"testing"

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
	org2, _ := iam.TestScopes(t, conn)

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
				authMethodId: "something",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "blank-userId",
			args: args{
				scopeId:      org.GetPublicId(),
				authMethodId: "something",
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
			name: "nonmatching-userid-scope",
			args: args{
				scopeId: org2.GetPublicId(),
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
				authMethodId: "something",
			},
			want: &Session{
				Session: &store.Session{
					IamScopeId:   org.GetPublicId(),
					IamUserId:    u.GetPublicId(),
					AuthMethodId: "something",
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

	orgs, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, orgs.GetPublicId())

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
				session:   &store.Session{AuthMethodId: "a changed id"},
			},
			wantErr: true,
		},
		{
			name: "immutable-scopeid",
			args: args{
				fieldMask: []string{"IamScopeId"},
				session:   &store.Session{IamScopeId: u.GetScopeId()},
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
	sess, err := NewSession(org.GetPublicId(), u.GetPublicId(), "something")
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
