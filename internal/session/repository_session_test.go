package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang/protobuf/ptypes"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	dbassert "github.com/hashicorp/boundary/internal/db/assert"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/oplog"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
			require.NoError(conn.Where("1=1").Delete(AllocSession()).Error)
			testSessions := []*Session{}
			for i := 0; i < tt.createCnt; i++ {
				s := TestSession(t, conn, wrapper, composedOf)
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
		require.NoError(conn.Where("1=1").Delete(AllocSession()).Error)
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestSession(t, conn, wrapper, composedOf)
		}
		got, err := repo.ListSessions(context.Background(), WithOrder("create_time asc"))
		require.NoError(err)
		assert.Equal(wantCnt, len(got))

		for i := 0; i < len(got)-1; i++ {
			first, err := ptypes.Timestamp(got[i].CreateTime.Timestamp)
			require.NoError(err)
			second, err := ptypes.Timestamp(got[i+1].CreateTime.Timestamp)
			require.NoError(err)
			assert.True(first.Before(second))
		}
	})
	t.Run("withUserId", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		require.NoError(conn.Where("1=1").Delete(AllocSession()).Error)
		wantCnt := 5
		for i := 0; i < wantCnt; i++ {
			_ = TestSession(t, conn, wrapper, composedOf)
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
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			s := &Session{
				UserId:      tt.args.composedOf.UserId,
				HostId:      tt.args.composedOf.HostId,
				TargetId:    tt.args.composedOf.TargetId,
				HostSetId:   tt.args.composedOf.HostSetId,
				AuthTokenId: tt.args.composedOf.AuthTokenId,
				ScopeId:     tt.args.composedOf.ScopeId,
			}
			ses, st, privKey, err := repo.CreateSession(context.Background(), wrapper, s)
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
			assert.NotNil(ses)
			assert.NotNil(privKey)
			assert.NotNil(st)
			assert.NotNil(ses.CreateTime)
			assert.NotNil(st.StartTime)
			assert.Equal(st.Status, StatusPending.String())
			foundSession, foundStates, err := repo.LookupSession(context.Background(), ses.PublicId)
			assert.NoError(err)
			assert.Equal(foundSession, ses)

			err = db.TestVerifyOplog(t, rw, ses.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_CREATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)

			require.Equal(1, len(foundStates))
			assert.Equal(foundStates[0].Status, StatusPending.String())
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
			name:         "cancelling",
			session:      TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus:    StatusCanceling,
			wantStateCnt: 2,
			wantErr:      false,
		},
		{
			name: "closed",
			session: func() *Session {
				s := TestDefaultSession(t, conn, wrapper, iamRepo)
				_ = TestState(t, conn, s.PublicId, StatusActive)
				return s
			}(),
			newStatus:    StatusTerminated,
			wantStateCnt: 3,
			wantErr:      false,
		},
		{
			name:      "bad-version",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: StatusCanceling,
			overrideSessionVersion: func() *uint32 {
				v := uint32(22)
				return &v
			}(),
			wantErr: true,
		},
		{
			name:      "empty-version",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: StatusCanceling,
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
			newStatus: StatusCanceling,
			overrideSessionId: func() *string {
				s := "s_thisIsNotValid"
				return &s
			}(),
			wantErr: true,
		},
		{
			name:      "empty-session",
			session:   TestDefaultSession(t, conn, wrapper, iamRepo),
			newStatus: StatusCanceling,
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

func TestRepository_ActivateState(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	tofu := TestTofu(t)
	tests := []struct {
		name                   string
		session                *Session
		overrideSessionId      *string
		overrideSessionVersion *uint32
		wantErr                bool
		wantIsError            error
	}{
		{
			name:    "valid",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			wantErr: false,
		},
		{
			name: "already-active",
			session: func() *Session {
				s := TestDefaultSession(t, conn, wrapper, iamRepo)
				activeSession, _, err := repo.ActivateSession(context.Background(), s.PublicId, s.Version, tofu)
				require.NoError(t, err)
				return activeSession
			}(),
			wantErr: true,
		},
		{
			name:    "bad-session-id",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionId: func() *string {
				id, err := newId()
				require.NoError(t, err)
				return &id
			}(),
			wantErr: true,
		},
		{
			name:    "bad-session-version",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionVersion: func() *uint32 {
				v := uint32(100)
				return &v
			}(),
			wantErr: true,
		},
		{
			name:    "empty-session-id",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionId: func() *string {
				id := ""
				return &id
			}(),
			wantErr:     true,
			wantIsError: db.ErrInvalidParameter,
		},
		{
			name:    "empty-session-version",
			session: TestDefaultSession(t, conn, wrapper, iamRepo),
			overrideSessionVersion: func() *uint32 {
				v := uint32(0)
				return &v
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
			s, ss, err := repo.ActivateSession(context.Background(), id, version, tofu)
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
			assert.Equal(tofu, s.TofuToken)
			assert.Equal(2, len(ss))
			assert.Equal(StatusActive.String(), ss[0].Status)
		})
		t.Run("already active", func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			session := TestDefaultSession(t, conn, wrapper, iamRepo)
			s, ss, err := repo.ActivateSession(context.Background(), session.PublicId, 1, tofu)
			require.NoError(err)
			require.NotNil(s)
			require.NotNil(ss)
			assert.Equal(2, len(ss))
			assert.Equal(StatusActive.String(), ss[0].Status)

			_, _, err = repo.ActivateSession(context.Background(), session.PublicId, 1, tofu)
			require.Error(err)

			_, _, err = repo.ActivateSession(context.Background(), session.PublicId, 2, tofu)
			require.Error(err)
		})
	}
}
func TestRepository_UpdateSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)
	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(t, err)

	newServerFunc := func() string {
		id, err := uuid.GenerateUUID()
		require.NoError(t, err)
		worker := &servers.Server{
			Name:        "test-session-worker-" + id,
			Type:        servers.ServerTypeWorker.String(),
			Description: "Test Session Worker",
			Address:     "127.0.0.1",
		}
		_, _, err = serversRepo.UpsertServer(context.Background(), worker)
		require.NoError(t, err)
		return worker.Name
	}

	type args struct {
		terminationReason TerminationReason
		serverId          string
		serverType        string
		tofu              []byte
		fieldMaskPaths    []string
		opt               []Option
		publicId          *string // not updateable - db.ErrInvalidFieldMask
		userId            string  // not updateable - db.ErrInvalidFieldMask
		hostId            string  // not updateable - db.ErrInvalidFieldMask
		targetId          string  // not updateable - db.ErrInvalidFieldMask
		hostSetId         string  // not updateable - db.ErrInvalidFieldMask
		authTokenId       string  // not updateable - db.ErrInvalidFieldMask
		scopeId           string  // not updateable - db.ErrInvalidFieldMask
	}
	tests := []struct {
		name           string
		args           args
		wantRowsUpdate int
		wantErr        bool
		wantIsError    error
	}{
		{
			name: "valid",
			args: args{
				terminationReason: Terminated,
				serverId:          newServerFunc(),
				serverType:        servers.ServerTypeWorker.String(),
				tofu:              TestTofu(t),
				fieldMaskPaths:    []string{"TerminationReason", "ServerId", "ServerType", "TofuToken"},
			},
			wantErr:        false,
			wantRowsUpdate: 1,
		},
		{
			name: "publicId",
			args: args{
				publicId: func() *string {
					id, err := newId()
					require.NoError(t, err)
					return &id
				}(),
				fieldMaskPaths: []string{"PublicId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "userId",
			args: args{
				userId: func() string {
					org, _ := iam.TestScopes(t, iamRepo)
					u := iam.TestUser(t, iamRepo, org.PublicId)
					return u.PublicId
				}(),
				fieldMaskPaths: []string{"UserId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "hostId",
			args: args{
				hostId: func() string {
					_, proj := iam.TestScopes(t, iamRepo)
					cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
					hosts := static.TestHosts(t, conn, cats[0].PublicId, 1)
					return hosts[0].PublicId
				}(),
				fieldMaskPaths: []string{"HostId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "targetId",
			args: args{
				targetId: func() string {
					_, proj := iam.TestScopes(t, iamRepo)
					tcpTarget := target.TestTcpTarget(t, conn, proj.PublicId, "test target")
					return tcpTarget.PublicId
				}(),
				fieldMaskPaths: []string{"TargetId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "hostSetId",
			args: args{
				hostSetId: func() string {
					_, proj := iam.TestScopes(t, iamRepo)
					cats := static.TestCatalogs(t, conn, proj.PublicId, 1)
					sets := static.TestSets(t, conn, cats[0].PublicId, 1)
					return sets[0].PublicId
				}(),
				fieldMaskPaths: []string{"HostSetId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "AuthTokenId",
			args: args{
				authTokenId: func() string {
					ctx := context.Background()
					org, _ := iam.TestScopes(t, iamRepo)
					authMethod := password.TestAuthMethods(t, conn, org.PublicId, 1)[0]
					acct := password.TestAccounts(t, conn, authMethod.GetPublicId(), 1)[0]
					user, err := iamRepo.LookupUserWithLogin(ctx, acct.GetPublicId(), iam.WithAutoVivify(true))
					require.NoError(t, err)

					authTokenRepo, err := authtoken.NewRepository(rw, rw, kms)
					require.NoError(t, err)
					at, err := authTokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
					require.NoError(t, err)
					return at.PublicId
				}(),
				fieldMaskPaths: []string{"AuthTokenId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
		{
			name: "ScopeId",
			args: args{
				scopeId: func() string {
					_, proj := iam.TestScopes(t, iamRepo)
					return proj.PublicId
				}(),
				fieldMaskPaths: []string{"ScopeId"},
			},
			wantErr:        true,
			wantRowsUpdate: 0,
			wantIsError:    db.ErrInvalidFieldMask,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)

			composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
			s := TestSession(t, conn, wrapper, composedOf)

			updateSession := AllocSession()
			updateSession.PublicId = s.PublicId
			if tt.args.publicId != nil {
				updateSession.PublicId = *tt.args.publicId
			}
			updateSession.ServerId = tt.args.serverId
			updateSession.ServerType = tt.args.serverType
			updateSession.TerminationReason = tt.args.terminationReason.String()
			if tt.args.tofu != nil {
				updateSession.TofuToken = make([]byte, len(tt.args.tofu))
				copy(updateSession.TofuToken, tt.args.tofu)
			}
			updateSession.Version = s.Version
			afterUpdateSession, afterUpdateState, updatedRows, err := repo.UpdateSession(context.Background(), &updateSession, updateSession.Version, tt.args.fieldMaskPaths, tt.args.opt...)

			if tt.wantErr {
				require.Error(err)
				if tt.wantIsError != nil {
					assert.Truef(errors.Is(err, tt.wantIsError), "unexpected error: %s", err.Error())
				}
				assert.Nil(afterUpdateSession)
				assert.Nil(afterUpdateState)
				assert.Equal(0, updatedRows)
				err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			require.NoError(err)
			assert.Equal(tt.wantRowsUpdate, updatedRows)
			require.NotNil(afterUpdateSession)
			require.NotNil(afterUpdateState)
			switch tt.name {
			case "valid-no-op":
				assert.Equal(s.UpdateTime, afterUpdateSession.UpdateTime)
			default:
				assert.NotEqual(s.UpdateTime, afterUpdateSession.UpdateTime)
			}
			foundSession, foundStates, err := repo.LookupSession(context.Background(), s.PublicId)
			require.NoError(err)
			assert.Equal(afterUpdateSession, foundSession)
			dbassrt := dbassert.New(t, rw)
			if tt.args.serverId == "" {
				dbassrt.IsNull(foundSession, "ServerId")
			}
			if tt.args.serverType == "" {
				dbassrt.IsNull(foundSession, "ServerType")
			}
			if tt.args.tofu == nil {
				dbassrt.IsNull(foundSession, "CtTofuToken")
				dbassrt.IsNull(foundSession, "KeyId")
			} else {
				dbassrt.NotNull(foundSession, "CtTofuToken")
				dbassrt.NotNull(foundSession, "KeyId")
			}
			assert.Equal(tt.args.terminationReason.String(), foundSession.TerminationReason)
			assert.Equal(tt.args.serverId, foundSession.ServerId)
			assert.Equal(tt.args.serverType, foundSession.ServerType)

			err = db.TestVerifyOplog(t, rw, s.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_UPDATE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)

			switch {
			case tt.args.terminationReason != "":
				require.Equal(2, len(foundStates))
				assert.Equal(StatusTerminated.String(), foundStates[0].Status)
				assert.Equal(StatusPending.String(), foundStates[1].Status)
			default:
				require.Equal(1, len(foundStates))
				assert.Equal(StatusPending.String(), foundStates[0].Status)
			}
		})
	}

}

func TestRepository_DeleteSession(t *testing.T) {
	t.Parallel()
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	kms := kms.TestKms(t, conn, wrapper)
	repo, err := NewRepository(rw, rw, kms)
	require.NoError(t, err)

	type args struct {
		session *Session
		opt     []Option
	}
	tests := []struct {
		name            string
		args            args
		wantRowsDeleted int
		wantErr         bool
		wantErrMsg      string
	}{
		{
			name: "valid",
			args: args{
				session: TestDefaultSession(t, conn, wrapper, iamRepo),
			},
			wantRowsDeleted: 1,
			wantErr:         false,
		},
		{
			name: "no-public-id",
			args: args{
				session: func() *Session {
					s := AllocSession()
					return &s
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete session: missing public id invalid parameter",
		},
		{
			name: "not-found",
			args: args{
				session: func() *Session {
					s := TestDefaultSession(t, conn, wrapper, iamRepo)
					id, err := newId()
					require.NoError(t, err)
					s.PublicId = id
					return s
				}(),
			},
			wantRowsDeleted: 0,
			wantErr:         true,
			wantErrMsg:      "delete session: failed record not found for ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert := assert.New(t)
			deletedRows, err := repo.DeleteSession(context.Background(), tt.args.session.PublicId, tt.args.opt...)
			if tt.wantErr {
				assert.Error(err)
				assert.Equal(0, deletedRows)
				assert.Contains(err.Error(), tt.wantErrMsg)
				err = db.TestVerifyOplog(t, rw, tt.args.session.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
				assert.Error(err)
				assert.True(errors.Is(db.ErrRecordNotFound, err))
				return
			}
			assert.NoError(err)
			assert.Equal(tt.wantRowsDeleted, deletedRows)
			foundSession, _, err := repo.LookupSession(context.Background(), tt.args.session.PublicId)
			assert.NoError(err)
			assert.Nil(foundSession)

			err = db.TestVerifyOplog(t, rw, tt.args.session.PublicId, db.WithOperation(oplog.OpType_OP_TYPE_DELETE), db.WithCreateNotBefore(10*time.Second))
			assert.Error(err)
		})
	}
}
