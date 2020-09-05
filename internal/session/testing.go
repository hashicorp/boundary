package session

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/servers"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/types/resource"
	wrapping "github.com/hashicorp/go-kms-wrapping"
	"github.com/hashicorp/go-uuid"
	"github.com/jinzhu/gorm"
	"github.com/stretchr/testify/require"
)

func TestState(t *testing.T, conn *gorm.DB, sessionId string, state Status) *State {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	s, err := NewState(sessionId, state)
	require.NoError(err)
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	return s
}

func TestSession(t *testing.T, conn *gorm.DB, c ComposedOf, opt ...Option) *Session {
	t.Helper()
	require := require.New(t)
	rw := db.New(conn)
	s, err := New(c, opt...)
	require.NoError(err)
	id, err := newId()
	require.NoError(err)
	s.PublicId = id
	err = rw.Create(context.Background(), s)
	require.NoError(err)
	return s
}

func TestDefaultSession(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository, opt ...Option) *Session {
	t.Helper()
	composedOf := TestSessionParams(t, conn, wrapper, iamRepo)
	return TestSession(t, conn, composedOf)
}

func TestSessionParams(t *testing.T, conn *gorm.DB, wrapper wrapping.Wrapper, iamRepo *iam.Repository) ComposedOf {
	t.Helper()
	ctx := context.Background()

	require := require.New(t)
	rw := db.New(conn)
	org, proj := iam.TestScopes(t, iamRepo)

	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)

	hosts := static.TestHosts(t, conn, cats[0].PublicId, 1)

	sets := static.TestSets(t, conn, cats[0].PublicId, 1)
	_ = static.TestSetMembers(t, conn, sets[0].PublicId, hosts)

	tcpTarget := target.TestTcpTarget(t, conn, proj.PublicId, "test target")

	kms := kms.TestKms(t, conn, wrapper)
	targetRepo, err := target.NewRepository(rw, rw, kms)
	require.NoError(err)
	_, _, err = targetRepo.AddTargetHostSets(ctx, tcpTarget.GetPublicId(), tcpTarget.GetVersion(), []string{sets[0].PublicId})
	require.NoError(err)

	authMethod := password.TestAuthMethods(t, conn, org.PublicId, 1)[0]
	acct := password.TestAccounts(t, conn, authMethod.GetPublicId(), 1)[0]
	user, err := iamRepo.LookupUserWithLogin(ctx, acct.GetPublicId(), iam.WithAutoVivify(true))
	require.NoError(err)

	authTokenRepo, err := authtoken.NewRepository(rw, rw, kms)
	require.NoError(err)
	at, err := authTokenRepo.CreateAuthToken(ctx, user, acct.GetPublicId())
	require.NoError(err)

	serversRepo, err := servers.NewRepository(rw, rw, kms)
	require.NoError(err)
	id := testId(t)
	worker := &servers.Server{
		PrivateId:   "test-session-worker-" + id,
		Name:        "test-session-worker-" + id,
		Type:        resource.Worker.String(),
		Description: "Test Session Worker",
		Address:     "127.0.0.1",
	}
	_, _, err = serversRepo.UpsertServer(ctx, worker)
	require.NoError(err)

	return ComposedOf{
		UserId:      user.PublicId,
		HostId:      hosts[0].PublicId,
		ServerId:    worker.PrivateId,
		ServerType:  worker.Type,
		TargetId:    tcpTarget.PublicId,
		HostSetId:   sets[0].PublicId,
		AuthTokenId: at.PublicId,
		ScopeId:     tcpTarget.ScopeId,
		Address:     "127.0.0.1",
		Port:        "22",
	}
}

func testId(t *testing.T) string {
	t.Helper()
	id, err := uuid.GenerateUUID()
	require.NoError(t, err)
	return id
}
