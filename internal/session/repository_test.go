package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/session/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestNewRepository(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	type args struct {
		r db.Reader
		w db.Writer
	}
	tests := []struct {
		name          string
		args          args
		want          *kms.Repository
		wantErr       bool
		wantErrString string
	}{
		{
			name: "valid",
			args: args{
				r: rw,
				w: rw,
			},
			want: func() *kms.Repository {
				ret, err := kms.NewRepository(rw, rw)
				require.NoError(t, err)
				return ret
			}(),
			wantErr: false,
		},
		{
			name: "nil-writer",
			args: args{
				r: rw,
				w: nil,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil writer",
		},
		{
			name: "nil-reader",
			args: args{
				r: nil,
				w: rw,
			},
			want:          nil,
			wantErr:       true,
			wantErrString: "error creating db repository with nil reader",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := kms.NewRepository(tt.args.r, tt.args.w)
			if tt.wantErr {
				require.Error(err)
				assert.Equal(err.Error(), tt.wantErrString)
				return
			}
			require.NoError(err)
			assert.Equal(tt.want, got)
		})
	}
}

func TestRepository_ListSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	const testLimit = 10
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	rw := db.New(conn)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms, WithLimit(testLimit))
	require.NoError(t, err)
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)

	type args struct {
		opt []Option
	}
	tests := []struct {
		name      string
		createCnt int
		args      args
		wantCnt   int
		wantErr   bool
	}{
		{
			name:      "no-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithLimit(-1)},
			},
			wantCnt: repo.defaultLimit + 1,
			wantErr: false,
		},
		{
			name:      "default-limit",
			createCnt: repo.defaultLimit + 1,
			args:      args{},
			wantCnt:   repo.defaultLimit,
			wantErr:   false,
		},
		{
			name:      "custom-limit",
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithLimit(3)},
			},
			wantCnt: 3,
			wantErr: false,
		},
		{
			name:      "withScopeId",
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithScopeId(composedOf.ScopeId)},
			},
			wantCnt: repo.defaultLimit,
			wantErr: false,
		},
		{
			name:      "bad-withScopeId",
			createCnt: repo.defaultLimit + 1,
			args: args{
				opt: []Option{WithScopeId("o_thisIsNotValid")},
			},
			wantCnt: 0,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			require.NoError(conn.Where("1=1").Delete(allocSession()).Error)
			testSessions := []*Session{}
			for i := 0; i < tt.createCnt; i++ {
				s := TestSession(t, conn, composedOf)
				testSessions = append(testSessions, s)
			}
			assert.Equal(tt.createCnt, len(testSessions))
			got, err := repo.ListSessions(context.Background(), tt.args.opt...)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantCnt, len(got))
		})
	}
	t.Run("withOrder", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		require.NoError(conn.Where("1=1").Delete(allocSession()).Error)
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestSession(t, conn, composedOf)
		}
		got, err := repo.ListSessions(context.Background(), WithOrder("create_time asc"))
		require.NoError(err)
		assert.Equal(wantCnt, len(got))

		for i := 0; i < len(got)-1; i++ {
			first, err := ptypes.Timestamp(got[i].GetCreateTime().Timestamp)
			require.NoError(err)
			second, err := ptypes.Timestamp(got[i+1].GetCreateTime().Timestamp)
			require.NoError(err)
			assert.True(first.Before(second))
		}
	})
	t.Run("withUserId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		require.NoError(conn.Where("1=1").Delete(allocSession()).Error)
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestSession(t, conn, composedOf)
		}
		s := TestDefaultSession(t, conn, wrapper, iamRepo)
		got, err := repo.ListSessions(context.Background(), WithUserId(s.UserId))
		require.NoError(err)
		assert.Equal(1, len(got))
		assert.Equal(got[0].UserId, s.UserId)
	})
}

func TestRepository_CreateSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	type args struct {
		composedOf ComposedOf
	}
	tests := []struct {
		name        string
		args        args
		wantErr     bool
		wantIsError error
	}{
		{
			name: "valid",
			args: args{
				composedOf: TestSessionParams(t, conn, wrapper, iamRepo),
			},
			wantErr: false,
		},
		{
			name: "empty-userId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.UserId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-hostId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.HostId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-serverId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ServerId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-serverType",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ServerType = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-targetId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.TargetId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-hostSetId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.HostSetId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-authTokenId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.AuthTokenId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-scopeId",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.ScopeId = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-address",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.Address = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name: "empty-port",
			args: args{
				composedOf: func() ComposedOf {
					c := TestSessionParams(t, conn, wrapper, iamRepo)
					c.Port = ""
					return c
				}(),
			},
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s := &Session{
				Session: &store.Session{
					UserId:      tt.args.composedOf.UserId,
					HostId:      tt.args.composedOf.HostId,
					ServerId:    tt.args.composedOf.ServerId,
					ServerType:  tt.args.composedOf.ServerType.String(),
					TargetId:    tt.args.composedOf.TargetId,
					SetId:       tt.args.composedOf.HostSetId,
					AuthTokenId: tt.args.composedOf.AuthTokenId,
					ScopeId:     tt.args.composedOf.ScopeId,
					Address:     tt.args.composedOf.Address,
					Port:        tt.args.composedOf.Port,
				},
			}
			ses, st, err := repo.CreateSession(context.Background(), s)
			if tt.wantErr {
				assert.Error(err)
				assert.Nil(ses)
				assert.Nil(st)
				if tt.wantIsError != nil {
					assert.True(errors.Is(err, tt.wantIsError))
				}
				return
			}
			require.NoError(err)
			assert.NotNil(ses.CreateTime)
			assert.NotNil(st.StartTime)
			assert.Equal(st.GetStatus(), Pending.String())
			foundSession, foundStates, err := repo.LookupSession(context.Background(), ses.PublicId)
			assert.NoError(err)
			assert.True(proto.Equal(foundSession, ses))

			err = db.TestVerifyOplog(t, rw, ses.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.NoError(err)

			require.Equal(1, len(foundStates))
			assert.Equal(foundStates[0].GetStatus(), Pending.String())
		})
	}
}

func TestRepository_UpdateState(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	tests := []struct {
		name                   string
		session                *Session
		newStatus              Status
		overrideSessionId      *string
		overrideSessionVersion *uint32
		wantStateCnt           int
		wantErr                bool
		wantIsError            error
	}{
		{
			name:         "connected",
			session:      TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus:    Connected,
			wantStateCnt: 2,
			wantErr:      false,
		},
		{
			name: "closed",
			session: func() *Session {
				s := TestDefaultSession(t, conn, wrapper, iamRepo)
				_ = TestState(t, conn, s.PublicId, Connected)
				return s
			}(),
			newStatus:    Closed,
			wantStateCnt: 3,
			wantErr:      false,
		},
		{
			name:      "bad-version",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: Connected,
			overrideSessionVersion: func() *uint32 {
				v := uint32(22)
				return &v
			}(),
			wantErr: true,
		},
		{
			name:      "empty-version",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: Connected,
			overrideSessionVersion: func() *uint32 {
				v := uint32(0)
				return &v
			}(),
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name:      "bad-sessionId",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: Connected,
			overrideSessionId: func() *string {
				s := "s_thisIsNotValid"
				return &s
			}(),
			wantErr: true,
		},
		{
			name:      "empty-session",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: Connected,
			overrideSessionId: func() *string {
				s := ""
				return &s
			}(),
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			var id string
			var version uint32
			switch {
			case tt.overrideSessionId != nil:
				id = *tt.overrideSessionId
			default:
				id = tt.session.PublicId
			}
			switch {
			case tt.overrideSessionVersion != nil:
				version = *tt.overrideSessionVersion
			default:
				version = tt.session.Version
			}

			s, ss, err := repo.UpdateState(context.Background(), id, version, tt.newStatus)
			if tt.wantErr {
				require.Error(err)
				if tt.wantIsError != nil {
					assert.Truef(errors.Is(err, tt.wantIsError), "unexpected error %s", err.Error())
				}
				return
			}
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(ss)
			assert.Equal(tt.wantStateCnt, len(ss))
			assert.Equal(tt.newStatus.String(), ss[0].Status)
		})
	}
}
