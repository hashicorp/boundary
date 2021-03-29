package migration

import (
	"context"
	"testing"

	"github.com/hashicorp/boundary/internal/auth/oidc"
	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/boundary/internal/errors"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AuthMethodSubtypes(t *testing.T) {
	t.Parallel()
	t.Run("oidc", func(t *testing.T) {
		assert, require := assert.New(t), require.New(t)
		ctx := context.Background()
		conn, _ := db.TestSetup(t, "postgres")
		rw := db.New(conn)
		rootWrapper := db.TestWrapper(t)
		kmsCache := kms.TestKms(t, conn, rootWrapper)
		iamRepo := iam.TestRepo(t, conn, rootWrapper)
		org, _ := iam.TestScopes(t, iamRepo)
		oidcRepo, err := oidc.NewRepository(rw, rw, kmsCache)
		require.NoError(err)

		// test subtype insert
		am, err := oidc.NewAuthMethod(org.PublicId, oidc.TestConvertToUrls(t, "https://alice.com")[0], "alice-rp", "fido", oidc.WithName("alice"))
		require.NoError(err)
		newAm, err := oidcRepo.CreateAuthMethod(ctx, am)
		require.NoError(err)
		p, err := findParent(t, rw, am.PublicId)
		require.NoError(err)
		assert.Equal(newAm.Name, p.Name)

		// test subtype update
		newAm.Name = "eve"
		updated, _, err := oidcRepo.UpdateAuthMethod(ctx, newAm, newAm.Version, []string{"Name"})
		require.NoError(err)
		p, err = findParent(t, rw, updated.PublicId)
		require.NoError(err)
		assert.Equal(updated.Name, p.Name)

		// test subtype delete
		_, err = oidcRepo.DeleteAuthMethod(ctx, updated.PublicId)
		require.NoError(err)
		p, err = findParent(t, rw, updated.PublicId)
		assert.Truef(errors.Match(errors.T(errors.RecordNotFound), err), "expected error code %s and got error: %q", errors.RecordNotFound, err)
		assert.Nil(p)
	})
}

type parent struct {
	PublicId string
	ScopeId  string
	Name     string
}

func (p *parent) GetPublicId() string { return p.PublicId }
func (p *parent) TableName() string   { return "auth_method" }

func findParent(t *testing.T, r db.Reader, authMethodId string) (*parent, error) {
	ctx := context.Background()
	t.Helper()
	p := &parent{
		PublicId: authMethodId,
	}
	err := r.LookupByPublicId(ctx, p)
	if err != nil {
		return nil, err
	}
	return p, nil
}
