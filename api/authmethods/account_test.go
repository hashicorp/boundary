package authmethods_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/auth/password"
	"github.com/hashicorp/boundary/internal/iam"
	"github.com/hashicorp/boundary/internal/servers/controller"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAccounts_List(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org := iam.TestOrg(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())

	accountClient := authmethods.NewAccountsClient(client)

	expected, apiErr, err := accountClient.List(tc.Context(), amId)
	assert.NoError(err)
	assert.NoError(apiErr)
	// A default account is created when a test controller is started.
	assert.Len(expected, 1)

	expected = append(expected, &authmethods.Account{Attributes: map[string]interface{}{"login_name": "loginname1"}})

	expected[1], apiErr, err = accountClient.Create(tc.Context(), amId, authmethods.WithPasswordAccountLoginName(expected[1].Attributes["login_name"].(string)))
	assert.NoError(err)
	assert.NoError(apiErr)

	ul, apiErr, err := accountClient.List(tc.Context(), amId)
	assert.NoError(err)
	assert.NoError(apiErr)
	assert.ElementsMatch(comparableSlice(expected[:2]), comparableSlice(ul))

	for i := 2; i < 10; i++ {
		newAcct, apiErr, err := accountClient.Create(tc.Context(), amId, authmethods.WithPasswordAccountLoginName(fmt.Sprintf("loginname%d", i)))
		expected = append(expected, newAcct)
		assert.NoError(err)
		assert.NoError(apiErr)
	}
	ul, apiErr, err = accountClient.List(tc.Context(), amId)
	require.NoError(err)
	assert.NoError(apiErr)
	assert.ElementsMatch(comparableSlice(expected), comparableSlice(ul))
}

func comparableSlice(in []*authmethods.Account) []authmethods.Account {
	var filtered []authmethods.Account
	for _, i := range in {
		p := authmethods.Account{
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

func TestAccount_Crud(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org := iam.TestOrg(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())

	accountClient := authmethods.NewAccountsClient(client)

	checkAccount := func(step string, u *authmethods.Account, apiErr error, err error, wantedName string, wantedVersion uint32) {
		assert.NoError(err, step)
		assert.NoError(apiErr, step)
		require.NotNil(u, "returned no resource", step)
		gotName := ""
		if u.Name != "" {
			gotName = u.Name
		}
		assert.Equal(wantedName, gotName, step)
		assert.EqualValues(wantedVersion, u.Version)
	}

	u, apiErr, err := accountClient.Create(tc.Context(), amId, authmethods.WithName("foo"), authmethods.WithPasswordAccountLoginName("loginname"))
	checkAccount("create", u, apiErr, err, "foo", 1)

	u, apiErr, err = accountClient.Read(tc.Context(), amId, u.Id)
	checkAccount("read", u, apiErr, err, "foo", 1)

	u, apiErr, err = accountClient.Update(tc.Context(), amId, u.Id, u.Version, authmethods.WithName("bar"))
	checkAccount("update", u, apiErr, err, "bar", 2)

	u, apiErr, err = accountClient.Update(tc.Context(), amId, u.Id, u.Version, authmethods.DefaultName())
	checkAccount("update", u, apiErr, err, "", 3)

	existed, _, err := accountClient.Delete(tc.Context(), amId, u.Id)
	require.NoError(err)
	assert.NoError(apiErr)
	assert.True(existed, "Expected existing account when deleted, but it wasn't.")

	existed, apiErr, err = accountClient.Delete(tc.Context(), amId, u.Id)
	require.NoError(err)
	assert.NoError(apiErr)
	assert.False(existed, "Expected account to not exist when deleted, but it did.")
}

func TestAccount_CustomMethods(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org := iam.TestOrg(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())

	accountClient := authmethods.NewAccountsClient(client)

	al, apiErr, err := accountClient.List(tc.Context(), amId)
	require.NoError(err)
	require.NoError(apiErr)
	require.Len(al, 1)

	acct := al[0]

	setAcct, apiErr, err := accountClient.SetPassword(tc.Context(), amId, acct.Id, "setpassword", acct.Version)
	require.NoError(err)
	require.NoError(apiErr)
	require.NotNil(setAcct)
	assert.Equal(acct.Version+1, setAcct.Version)

	changeAcct, apiErr, err := accountClient.ChangePassword(tc.Context(), amId, acct.Id, "setpassword", "changepassword", setAcct.Version)
	require.NoError(err)
	require.NoError(apiErr)
	require.NotNil(changeAcct)
	assert.Equal(setAcct.Version+1, changeAcct.Version)
}

func TestAccount_Errors(t *testing.T) {
	assert, require := assert.New(t), require.New(t)
	amId := "paum_1234567890"
	tc := controller.NewTestController(t, &controller.TestControllerOpts{
		DisableAuthorizationFailures: true,
		DefaultAuthMethodId:          amId,
		DefaultLoginName:             "user",
		DefaultPassword:              "passpass",
	})
	defer tc.Shutdown()

	client := tc.Client()
	org := iam.TestOrg(t, tc.IamRepo())
	client.SetScopeId(org.GetPublicId())

	accountClient := authmethods.NewAccountsClient(client)

	u, apiErr, err := accountClient.Create(tc.Context(), amId, authmethods.WithPasswordAccountLoginName("first"))
	require.NoError(err)
	assert.NoError(apiErr)
	assert.NotNil(u)

	// Create another resource with the same name.
	_, apiErr, err = accountClient.Create(tc.Context(), amId, authmethods.WithPasswordAccountLoginName("first"))
	require.NoError(err)
	assert.Error(apiErr)

	_, apiErr, err = accountClient.Read(tc.Context(), amId, password.AccountPrefix+"_doesntexis")
	require.NoError(err)
	assert.Error(apiErr)
	assert.True(errors.Is(apiErr, api.ErrNotFound))

	_, apiErr, err = accountClient.Read(tc.Context(), amId, "invalid id")
	require.NoError(err)
	assert.Error(apiErr)
	assert.True(errors.Is(apiErr, api.ErrForbidden))

	_, apiErr, err = accountClient.Update(tc.Context(), amId, u.Id, u.Version)
	require.NoError(err)
	assert.Error(apiErr)
	assert.True(errors.Is(apiErr, api.ErrBadRequest))
}
