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
	org := iam.TestOrg(t, tc.IamRepo(), iam.WithUserId(token.UserId))
	amClient := authmethods.NewClient(client)
	am, apiErr, err := amClient.Create(tc.Context(), "password", org.GetPublicId())
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(am)

	accountClient := accounts.NewClient(client)

	expected, apiErr, err := accountClient.List(tc.Context(), am.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.Len(expected, 0)

	expected = append(expected, &accounts.Account{Attributes: map[string]interface{}{"login_name": "loginname0"}})

	expected[0], apiErr, err = accountClient.Create(tc.Context(), am.Id, accounts.WithPasswordAccountLoginName(expected[0].Attributes["login_name"].(string)))
	assert.NoError(err)
	assert.Nil(apiErr)

	ul, apiErr, err := accountClient.List(tc.Context(), am.Id)
	assert.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:1]), comparableSlice(ul))

	for i := 1; i < 10; i++ {
		newAcct, apiErr, err := accountClient.Create(tc.Context(), am.Id, accounts.WithPasswordAccountLoginName(fmt.Sprintf("loginname%d", i)))
		expected = append(expected, newAcct)
		assert.NoError(err)
		assert.Nil(apiErr)
	}
	ul, apiErr, err = accountClient.List(tc.Context(), am.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul))
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
	checkAccount("create", u, apiErr, err, "foo", 1)

	u, apiErr, err = accountClient.Read(tc.Context(), u.Id)
	checkAccount("read", u, apiErr, err, "foo", 1)

	u, apiErr, err = accountClient.Update(tc.Context(), u.Id, u.Version, accounts.WithName("bar"))
	checkAccount("update", u, apiErr, err, "bar", 2)

	u, apiErr, err = accountClient.Update(tc.Context(), u.Id, u.Version, accounts.DefaultName())
	checkAccount("update", u, apiErr, err, "", 3)

	existed, _, err := accountClient.Delete(tc.Context(), u.Id)
	require.NoError(err)
	assert.Nil(apiErr)
	assert.True(existed, "Expected existing account when deleted, but it wasn't.")
}

func TestCustomMethods(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	token := tc.Token()
	client := tc.Client()
	amId := token.AuthMethodId

	accountClient := accounts.NewClient(client)

	al, apiErr, err := accountClient.List(tc.Context(), amId)
	require.NoError(err)
	require.Nil(apiErr)
	require.Len(al, 1)

	acct := al[0]

	setAcct, apiErr, err := accountClient.SetPassword(tc.Context(), acct.Id, "setpassword", acct.Version)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(setAcct)
	assert.Equal(acct.Version+1, setAcct.Version)

	changeAcct, apiErr, err := accountClient.ChangePassword(tc.Context(), acct.Id, "setpassword", "changepassword", setAcct.Version)
	require.NoError(err)
	require.Nil(apiErr)
	require.NotNil(changeAcct)
	assert.Equal(setAcct.Version+1, changeAcct.Version)
}

func TestErrors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	tc := controller.NewTestController(t, nil)
	defer tc.Shutdown()

	client := tc.Client()
	token := tc.Token()
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
	assert.EqualValues(http.StatusForbidden, apiErr.Status)

	_, apiErr, err = accountClient.Read(tc.Context(), "invalid id")
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)

	_, apiErr, err = accountClient.Update(tc.Context(), u.Id, u.Version)
	require.NoError(err)
	assert.NotNil(apiErr)
	assert.EqualValues(http.StatusBadRequest, apiErr.Status)
}
