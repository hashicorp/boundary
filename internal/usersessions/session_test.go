package usersessions

import (
	"context"
	"testing"

	"github.com/hashicorp/watchtower/internal/db"
	"github.com/hashicorp/watchtower/internal/iam"
	"github.com/hashicorp/watchtower/internal/usersessions/store"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/assert"
)

func TestSession_New(t *testing.T) {
	cleanup, conn, _ := db.TestSetup(t, "postgres")
	defer func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}()

	org, _ := iam.TestScopes(t, conn)

	type args struct {
		scopeId string
		opts    []Option
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
				scopeId: "",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "valid-no-options",
			args: args{
				scopeId: org.GetPublicId(),
			},
			want: &Session{
				Session: &store.Session{
					IamScopeId: org.GetPublicId(),
				},
			},
		},
		{
			name: "valid-with-name",
			args: args{
				scopeId: org.GetPublicId(),
				opts: []Option{
					WithName("test-name"),
				},
			},
			want: &Session{
				Session: &store.Session{
					IamScopeId: org.GetPublicId(),
				},
			},
		},
		{
			name: "valid-with-description",
			args: args{
				scopeId: org.GetPublicId(),
				opts: []Option{
					WithDescription("test-description"),
				},
			},
			want: &Session{
				Session: &store.Session{
					IamScopeId: org.GetPublicId(),
				},
			},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			got, err := NewSession(tt.args.scopeId, tt.args.opts...)
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

					w := db.New(conn)
					err2 := w.Create(context.Background(), got)
					assert.NoError(err2)
				}
			}
		})
	}
}

func testSession(t *testing.T, conn *gorm.DB) *Session {
	t.Helper()
	assert := assert.New(t)
	org, _ := iam.TestScopes(t, conn)
	u := iam.TestUser(t, conn, org.GetPublicId())
	sess, err := NewSession(org.GetPublicId(), u.GetPublicId(), "")
	assert.NoError(err)
	assert.NotNil(sess)
	id, err := newSessionId()
	assert.NoError(err)
	assert.NotEmpty(id)
	sess.PublicId = id

	w := db.New(conn)
	err2 := w.Create(context.Background(), sess)
	assert.NoError(err2)
	return sess
}
