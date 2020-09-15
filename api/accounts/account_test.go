package accounts_test

import (
	"fmt"
	"net/http"
	"os"
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
	os.Setenv("BOUNDARY_LOG_URLS", "1")
	os.Setenv("BOUNDARY_DEV_SKIP_AUTHZ", "1")
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
	amResult, apiErr, err := amClient.Create(tc.Context(), "password", org.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(amResult)
	am := amResult.Item

	accountClient := accounts.NewClient(client)

	lr, apiErr, err := accountClient.List(tc.Context(), am.Id)
	require.NoError(err)
	require.Nil(apiErr)
	expected := lr.Items
	assert.Len(expected, 0)

	expected = append(expected, &accounts.Account{Attributes: map[string]interface{}{"login_name": "loginname0"}})

	cr, apiErr, err := accountClient.Create(tc.Context(), am.Id, accounts.WithPasswordAccountLoginName(expected[0].Attributes["login_name"].(string)))
	require.NoError(err)
	require.Nil(apiErr)
	expected[0] = cr.Item

	ulResult, apiErr, err := accountClient.List(tc.Context(), am.Id)
	require.NoError(err)
	require.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ulResult.Items))

	for i := 1; i < 10; i++ {
		newAcctResult, apiErr, err := accountClient.Create(tc.Context(), am.Id, accounts.WithPasswordAccountLoginName(fmt.Sprintf("loginname%d", i)))
		require.NoError(err)
		require.Nil(apiErr)
		expected = append(expected, newAcctResult.Item)
	}
	ulResult, apiErr, err = accountClient.List(tc.Context(), am.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ulResult.Items))
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

	checkAccount := func(step string, u *accounts.Account, apiErr *api.Error, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		if !assert.Nil(apiErr, step) && apiErr.Message != "" {
			t.Errorf("ApiError message: %q", apiErr.Message)
		}
		require.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, apiErr, err := accountClient.Create(tc.Context(), amId, accounts.WithName("foo"), accounts.WithPasswordAccountLoginName("loginname"))
	checkAccount("create", u.Item, apiErr, err, "foo", 1)

	u, apiErr, err = accountClient.Read(tc.Context(), u.Item.Id)
	checkAccount("read", u.Item, apiErr, err, "foo", 1)

	u, apiErr, err = accountClient.Update(tc.Context(), u.Item.Id, u.Item.Version, accounts.WithName("bar"))
	checkAccount("update", u.Item, apiErr, err, "bar", 2)

	u, apiErr, err = accountClient.Update(tc.Context(), u.Item.Id, u.Item.Version, accounts.DefaultName())
	checkAccount("update", u.Item, apiErr, err, "", 3)

	_, apiErr, err = accountClient.Delete(tc.Context(), u.Item.Id)
	require.NoError(err)
	assert.Nil(apiErr)
}

func TestCustomMethods(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
	client.SetToken(token.Token)
	amId := token.AuthMethodId

	accountClient := accounts.NewClient(client)

	al, apiErr, err := accountClient.List(tc.Context(), amId)
	require.NoError(err)
	require.Nil(apiErr)
	require.Len(al.Items, 1)

	acct := al.Items[0]

	setAcct, apiErr, err := accountClient.SetPassword(tc.Context(), acct.Id, "setpassword", acct.Version)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(setAcct)
	assert.Equal(acct.Version+1, setAcct.Item.Version)

	changeAcct, apiErr, err := accountClient.ChangePassword(tc.Context(), acct.Id, "setpassword", "changepassword", setAcct.Item.Version)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(changeAcct)
	assert.Equal(setAcct.Item.Version+1, changeAcct.Item.Version)
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

	u, apiErr, err := accountClient.Create(tc.Context(), amId, accounts.WithPasswordAccountLoginName("first"))
	require.NoError(err)
	assert.Nil(apiErr)
	assert.NotNil(u)

	// Create another resource with the same name.
	_, apiErr, err = accountClient.Create(tc.Context(), amId, accounts.WithPasswordAccountLoginName("first"))
	require.NoError(err)
	assert.NotNil(apiErr)

	_, apiErr, err = accountClient.Read(tc.Context(), password.AccountPrefix+"_doesntexis")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusNotFound, apiErr.Status)

	_, apiErr, err = accountClient.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)

	_, apiErr, err = accountClient.Update(tc.Context(), u.Item.Id, u.Item.Version)
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
