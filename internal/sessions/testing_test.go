package sessions

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
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestSession(t *testing.T) {
	t.Helper()
	ctx := context.Background()

	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	rw := db.New(conn)
	wrapper := db.TestWrapper(t)
	iamRepo := iam.TestRepo(t, conn, wrapper)
	org, proj := iam.TestScopes(t, iamRepo)

	cats := static.TestCatalogs(t, conn, proj.PublicId, 1)

	hosts := static.TestHosts(t, conn, cats[0].PublicId, 1)

	sets := static.TestSets(t, conn, cats[0].PublicId, 1)
	_ = static.TestSetMembers(t, conn, sets[0].PublicId, hosts)

	tcpTarget := target.TestTcpTarget(t, conn, proj.PublicId, "test target")

	kms := kms.TestKms(t, conn, wrapper)
	targetRepo, err := target.NewRepository(rw, rw, kms)
	require.NoError(err)
	_, _, err = targetRepo.AddTargeHostSets(ctx, tcpTarget.GetPublicId(), tcpTarget.GetVersion(), []string{sets[0].PublicId})
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

	s := TestSession(
		t,
		conn,
		user.PublicId,
		hosts[0].PublicId,
		worker.PrivateId,
		worker.Type,
		tcpTarget.PublicId,
		sets[0].PublicId,
		at.PublicId,
		user.ScopeId, // for now, we pick the user scope as the session scope
		"127.0.0.1",
		"22")
	require.NotNil(s)
	assert.NotEmpty(s.PublicId)
}
