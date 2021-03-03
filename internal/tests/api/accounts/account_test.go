package accounts_test

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/auth/password"
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
	require.NotNil(client)
	token := tc.Token()
	require.NotNil(token)
	client.SetToken(token.Token)
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	amClient := authmethods.NewClient(client)
	amResult, err := amClient.Create(tc.Context(), "password", org.GetPublicId())
	require.NoError(err)
	require.NotNil(amResult)
	am := amResult.Item

	accountClient := accounts.NewClient(client)

	lr, err := accountClient.List(tc.Context(), am.Id)
	require.NoError(err)
	expected := lr.Items
	assert.Len(expected, 0)

	expected = append(expected, &accounts.Account{Attributes: map[string]interface{}{"login_name": "loginname0"}})

	cr, err := accountClient.Create(tc.Context(), am.Id, accounts.WithPasswordAccountLoginName(expected[0].Attributes["login_name"].(string)))
	require.NoError(err)
	expected[0] = cr.Item

	ulResult, err := accountClient.List(tc.Context(), am.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ulResult.Items))

	for i := 1; i < 10; i++ {
		newAcctResult, err := accountClient.Create(tc.Context(), am.Id, accounts.WithPasswordAccountLoginName(fmt.Sprintf("loginname%d", i)))
		require.NoError(err)
		expected = append(expected, newAcctResult.Item)
	}
	ulResult, err = accountClient.List(tc.Context(), am.Id)
	require.NoError(err)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ulResult.Items))

	filterItem := expected[3]
	ulResult, err = accountClient.List(tc.Context(), am.Id,
		accounts.WithFilter(fmt.Sprintf(`"/item/attributes/login_name"==%q`, filterItem.Attributes["login_name"])))
	require.NoError(err)
	assert.Len(ulResult.Items, 1)
	assert.Equal(filterItem.Id, ulResult.Items[0].Id)
}

func comparableSlice(in []*accounts.Account) []accounts.Account {
	var filtered []accounts.Account
	for _, i := range in {
		p := accounts.Account{
			Id:          i.Id,
			Name:        i.Name,
			Description: i.Description,
			CreatedTime: i.CreatedTime,
			UpdatedTime: i.UpdatedTime,
			Attributes:  i.Attributes,
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
	amId := token.AuthMethodId
	accountClient := accounts.NewClient(client)

	checkAccount := func(step string, u *accounts.Account, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		require.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, err := accountClient.Create(tc.Context(), amId, accounts.WithName("foo"), accounts.WithPasswordAccountLoginName("loginname"))
	checkAccount("create", u.Item, err, "foo", 1)

	u, err = accountClient.Read(tc.Context(), u.Item.Id)
	checkAccount("read", u.Item, err, "foo", 1)

	u, err = accountClient.Update(tc.Context(), u.Item.Id, u.Item.Version, accounts.WithName("bar"))
	checkAccount("update", u.Item, err, "bar", 2)

	u, err = accountClient.Update(tc.Context(), u.Item.Id, u.Item.Version, accounts.DefaultName())
	checkAccount("update", u.Item, err, "", 3)

	_, err = accountClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)
}

func TestCustomMethods(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amId := token.AuthMethodId

	adminAccountClient := accounts.NewClient(client)
	client = client.Clone()
	client.SetToken(tc.UnprivilegedToken().Token)
	userAccountClient := accounts.NewClient(client)

	al, err := adminAccountClient.List(tc.Context(), amId)
	require.NoError(err)
	require.Len(al.Items, 2)

	userAcct := al.Items[0]
	if userAcct.Name == "admin" {
		userAcct = al.Items[1]
	}

	_, err = userAccountClient.SetPassword(tc.Context(), userAcct.Id, "setpassword", userAcct.Version)
	require.Error(err)

	setAcct, err := adminAccountClient.SetPassword(tc.Context(), userAcct.Id, "setpassword", userAcct.Version)
	require.NoError(err)
	require.NotNil(setAcct)
	assert.Equal(userAcct.Version+1, setAcct.Item.Version)

	changeAcct, err := adminAccountClient.ChangePassword(tc.Context(), userAcct.Id, "setpassword", "changepassword", setAcct.Item.Version)
	require.NoError(err)
	require.NotNil(changeAcct)
	assert.Equal(userAcct.Version+2, changeAcct.Item.Version)

	changeAcct, err = userAccountClient.ChangePassword(tc.Context(), userAcct.Id, "changepassword", "password2", changeAcct.Item.Version)
	require.NoError(err)
	require.NotNil(changeAcct)
	assert.Equal(userAcct.Version+3, changeAcct.Item.Version)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amId := token.AuthMethodId
	accountClient := accounts.NewClient(client)

	u, err := accountClient.Create(tc.Context(), amId, accounts.WithPasswordAccountLoginName("first"))
	require.NoError(err)
	assert.NotNil(u)

	// Updating the wrong version should fail.
	_, err = accountClient.Update(tc.Context(), u.Item.Id, 73, accounts.WithName("anything"))
	require.Error(err)
	apiErr := api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	// Create another resource with the same name.
	_, err = accountClient.Create(tc.Context(), amId, accounts.WithPasswordAccountLoginName("first"))
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)

	_, err = accountClient.Read(tc.Context(), password.AccountPrefix+"_doesntexis")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Response().StatusCode())

	_, err = accountClient.Read(tc.Context(), "invalid id")
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())

	_, err = accountClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.Error(err)
	apiErr = api.AsServerError(err)
	require.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Response().StatusCode())
}
