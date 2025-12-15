// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package vault_test

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/globals"
	"github.com/hashicorp/boundary/internal/authtoken"
	"github.com/hashicorp/boundary/internal/credential/vault"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/host/static"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/hashicorp/boundary/internal/session"
	"github.com/hashicorp/boundary/internal/target"
	"github.com/hashicorp/boundary/internal/target/tcp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_TestCredentials(t *testing.T) {
	t.Parallel()
	assert, require := assert.New(t), require.New(t)
	conn, _ := db.TestSetup(t, "postgres")
	wrapper := db.TestWrapper(t)
	kms := kms.TestKms(t, conn, wrapper)

	org, prj := iam.TestScopes(t, iam.TestRepo(t, conn, wrapper))
	require.NotNil(prj)
	assert.NotEmpty(prj.GetPublicId())

	cs := vault.TestCredentialStores(t, conn, wrapper, prj.GetPublicId(), 1)[0]
	cl := vault.TestCredentialLibraries(t, conn, wrapper, cs.GetPublicId(), globals.UnspecifiedCredentialType, 1)[0]

	hc := static.TestCatalogs(t, conn, prj.GetPublicId(), 1)[0]
	hs := static.TestSets(t, conn, hc.GetPublicId(), 1)[0]
	h := static.TestHosts(t, conn, hc.GetPublicId(), 1)[0]
	static.TestSetMembers(t, conn, hs.GetPublicId(), []*static.Host{h})

	tar := tcp.TestTarget(context.Background(), t, conn, prj.GetPublicId(), "test", target.WithHostSources([]string{hs.GetPublicId()}))
	target.TestCredentialLibrary(t, conn, tar.GetPublicId(), cl.GetPublicId(), string(cl.CredentialType()))

	at := authtoken.TestAuthToken(t, conn, kms, org.GetPublicId())
	uId := at.GetIamUserId()

	sess := session.TestSession(t, conn, wrapper, session.ComposedOf{
		UserId:      uId,
		HostId:      h.GetPublicId(),
		TargetId:    tar.GetPublicId(),
		HostSetId:   hs.GetPublicId(),
		AuthTokenId: at.GetPublicId(),
		ProjectId:   prj.GetPublicId(),
		Endpoint:    "tcp://127.0.0.1:22",
	})

	count := 4
	credentials := vault.TestCredentials(t, conn, wrapper, cl.GetPublicId(), sess.GetPublicId(), count)
	assert.Len(credentials, count)
	for _, credential := range credentials {
		assert.NotEmpty(credential.GetPublicId())
	}
}
