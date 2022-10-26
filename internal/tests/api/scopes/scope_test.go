package scopes_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/scopes"
	"github.com/hashicorp/boundary/internal/daemon/controller"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestList(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	scps := scopes.NewClient(client)

	pl, err := scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.Empty(pl.Items)

	expected := make([]*scopes.Scope, 10)
	for i := 0; i < 10; i++ {
		scr, err := scps.Create(tc.Context(), org.GetPublicId(), scopes.WithName(fmt.Sprintf("%d", i)))
		require.NoError(err)
		expected[i] = scr.Item
	}
	pl, err = scps.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(pl.Items))

	filterItem := pl.Items[3]
	pl, err = scps.List(tc.Context(), org.GetPublicId(),
		scopes.WithFilter(fmt.Sprintf(`"/item/id"==%q`, filterItem.Id)))
	require.NoError(err)
	assert.Len(pl.Items, 1)
	assert.Equal(filterItem.Id, pl.Items[0].Id)
}

func comparableSlice(in []*scopes.Scope) []scopes.Scope {
	var filtered []scopes.Scope
	for _, i := range in {
		p := scopes.Scope{
			Id:          i.Id,
			ScopeId:     i.ScopeId,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
		}
		filtered = append(filtered, p)
	}
	return filtered
}

func TestCrud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	scps := scopes.NewClient(client)

	checkProject := func(step string, s *scopes.Scope, err error, wantedName string, wantedVersion uint32) {
		require.NoError(err, step)
		assert.NotNil(s, "returned project", step)
		gotName := ""
		if s.Name != "" {
			gotName = s.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.Equal(wantedVersion, s.Version)
	}

	s, err := scps.Create(tc.Context(), org.GetPublicId(), scopes.WithName("foo"))
	checkProject("create", s.Item, err, "foo", 1)

	s, err = scps.Read(tc.Context(), s.Item.Id)
	checkProject("read", s.Item, err, "foo", 1)

	s, err = scps.Update(tc.Context(), s.Item.Id, s.Item.Version, scopes.WithName("bar"))
	checkProject("update", s.Item, err, "bar", 2)

	s, err = scps.Update(tc.Context(), s.Item.Id, s.Item.Version, scopes.DefaultName())
	checkProject("update, unset name", s.Item, err, "", 3)

	_, err = scps.Delete(tc.Context(), s.Item.Id)
	require.NoError(err)

	_, err = scps.Delete(tc.Context(), s.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org, _ := iam.TestScopes(t, tc.IamRepo(), iam.WithUserId(token.UserId))

	scps := scopes.NewClient(client)

	createdProj, err := scps.Create(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.NotNil(createdProj)

	// A malformed id is processed as the id and not a different path to the api.
	_, err = scps.Read(tc.Context(), fmt.Sprintf("%s/../", createdProj.Item.Id))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
	require.Len(apiErr.Details.RequestFields, 1)
	assert.Equal(apiErr.Details.RequestFields[0].Name, "id")

	// Updating the wrong version should fail.
	_, err = scps.Update(tc.Context(), createdProj.Item.Id, 73, scopes.WithName("anything"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = scps.Read(tc.Context(), "p_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = scps.Read(tc.Context(), "invalid id")
	assert.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}

func TestKeyDestruction(t *testing.T) {
	ctx := context.Background()
	tc := controller.NewTestController(t, &controller.TestControllerOpts{SchedulerRunJobInterval: time.Second})
	t.Cleanup(tc.Shutdown)
	c := tc.Client()
	c.SetToken(tc.Token().Token)
	sc := scopes.NewClient(c)

	keys, err := sc.ListKeys(ctx, "global")
	require.NoError(t, err)
	assert.Len(t, keys.Items, 7)
	for _, key := range keys.Items {
		assert.Len(t, key.Versions, 1)
	}

	_, err = sc.RotateKeys(ctx, "global", false)
	require.NoError(t, err)

	keys, err = sc.ListKeys(ctx, "global")
	require.NoError(t, err)
	assert.Len(t, keys.Items, 7)
	for _, key := range keys.Items {
		assert.Len(t, key.Versions, 2)
	}

	// Root key is always last, by virtue of sorting by ID
	rootKeyVersion := keys.Items[len(keys.Items)-1].Versions[1]
	var destroyKeyVersion *scopes.KeyVersion
	for _, key := range keys.Items {
		if key.Purpose == kms.KeyPurposeDatabase.String() {
			destroyKeyVersion = key.Versions[1]
		}
	}

	jobs, err := sc.ListKeyVersionDestructionJobs(ctx, "global")
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 0)

	result, err := sc.DestroyKeyVersion(ctx, "global", rootKeyVersion.Id)
	require.NoError(t, err)
	assert.Equal(t, "completed", result.State)

	jobs, err = sc.ListKeyVersionDestructionJobs(ctx, "global")
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 0)

	keys, err = sc.ListKeys(ctx, "global")
	require.NoError(t, err)
	assert.Len(t, keys.Items, 7)
	for _, key := range keys.Items {
		switch key.Purpose {
		case "rootKey":
			assert.Len(t, key.Versions, 1)
		default:
			assert.Len(t, key.Versions, 2)
		}
	}

	result, err = sc.DestroyKeyVersion(ctx, "global", destroyKeyVersion.Id)
	require.NoError(t, err)
	assert.Equal(t, "pending", result.State)

	jobs, err = sc.ListKeyVersionDestructionJobs(ctx, "global")
	require.NoError(t, err)
	assert.Len(t, jobs.Items, 1)

	// The configured scheduler monitoring interval is 1 second. The jobs become available 1
	// second after the last successful run. We need to re-encrypt data in 4 different tables,
	// and then we need to destroy the key. This job will take between 4 and 5 seconds to run,
	// depending on the timing of the first started run.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	t.Cleanup(cancel)
	for {
		jobs, err = sc.ListKeyVersionDestructionJobs(ctx, "global")
		require.NoError(t, err)
		if len(jobs.Items) == 0 {
			break
		}
		select {
		case <-time.After(time.Second):
		case <-ctx.Done():
			t.Log(jobs.GetItems()[0])
			t.Fatal("Test timed out waiting for destruction to finish")
		}
	}

	keys, err = sc.ListKeys(ctx, "global")
	require.NoError(t, err)
	assert.Len(t, keys.Items, 7)
	for _, key := range keys.Items {
		switch key.Purpose {
		case "rootKey", "database":
			assert.Len(t, key.Versions, 1)
		default:
			assert.Len(t, key.Versions, 2)
		}
	}
}
