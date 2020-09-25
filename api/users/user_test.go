package users_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/users"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
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
	userClient := users.NewClient(client)

	ul, err := userClient.List(tc.Context(), org.GetPublicId())
	assert.NoError(err)
	assert.Empty(ul.Items)

	var expected []*users.User
	for i := 0; i < 10; i++ {
		expected = append(expected, &users.User{Name: fmt.Sprint(i)})
	}

	ucr, err := userClient.Create(tc.Context(), org.GetPublicId(), users.WithName(expected[0].Name))
	assert.NoError(err)
	expected[0] = ucr.Item

	ul, err = userClient.List(tc.Context(), org.GetPublicId())
	assert.NoError(err)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul.Items))

	for i := 1; i < 10; i++ {
		ucr, err = userClient.Create(tc.Context(), org.GetPublicId(), users.WithName(expected[i].Name))
		assert.NoError(err)
		expected[i] = ucr.Item
	}
	ul, err = userClient.List(tc.Context(), org.GetPublicId())
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul.Items))
}

func comparableSlice(in []*users.User) []users.User {
	var filtered []users.User
	for _, i := range in {
		p := users.User{
			Id:          i.Id,
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
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	userClient := users.NewClient(client)

	checkUser := func(step string, u *users.User, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		assert.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, err := userClient.Create(tc.Context(), org.GetPublicId(), users.WithName("foo"))
	checkUser("create", u.Item, err, "foo", 1)

	u, err = userClient.Read(tc.Context(), u.Item.Id)
	checkUser("read", u.Item, err, "foo", 1)

	u, err = userClient.Update(tc.Context(), u.Item.Id, u.Item.Version, users.WithName("bar"))
	checkUser("update", u.Item, err, "bar", 2)

	u, err = userClient.Update(tc.Context(), u.Item.Id, u.Item.Version, users.DefaultName())
	checkUser("update", u.Item, err, "", 3)

	_, err = userClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)

	_, err = userClient.Delete(tc.Context(), u.Item.Id)
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	userClient := users.NewClient(client)

	u, err := userClient.Create(tc.Context(), org.GetPublicId(), users.WithName("first"))
	require.NoError(err)
	assert.NotNil(u)

	// Updating the wrong version should fail.
	_, err = userClient.Update(tc.Context(), u.Item.Id, 73, users.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	// Create another resource with the same name.
	_, err = userClient.Create(tc.Context(), org.GetPublicId(), users.WithName("first"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)

	_, err = userClient.Read(tc.Context(), iam.UserPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, err = userClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)

	_, err = userClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
