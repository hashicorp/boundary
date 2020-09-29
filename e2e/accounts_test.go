// +build integration

package e2e

import (
	"errors"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/api/accounts"
	"github.com/stretchr/testify/assert"
)

const (
	acctCmd      = "accounts"
	kindPassword = "password"
)

type testAccount struct {
	account *accounts.Account
}

func (x *testAccount) create(t *testing.T, kind string) error {
	if kind == "" {
		kind = kindPassword
	}

	if x.account.Attributes == nil {
		return errors.New("account attrs must not be nil")
	}

	createCase := testCase{
		cmd:      boundary,
		resource: acctCmd,
		action:   create,
		args: []string{
			"password",
			"-auth-method-id", x.account.AuthMethodId,
			"-login-name", x.account.Attributes["login_name"].(string),
			"-password", x.account.Attributes["password"].(string),
			"-name", x.account.Name,
			"-description", x.account.Description,
			"-format", "json"},
	}
	x.account = caseRunner(createCase, x.account, t).(*accounts.Account)
	return nil
}

func (x *testAccount) read(t *testing.T) error {
	readCase := testCase{
		cmd:      boundary,
		resource: acctCmd,
		action:   read,
		args: []string{
			"-id", x.account.Id,
			"-format", "json"},
	}
	x.account = caseRunner(readCase, x.account, t).(*accounts.Account)
	return nil
}

func (x *testAccount) update(t *testing.T) error {
	updateCase := testCase{
		cmd:      boundary,
		resource: acctCmd,
		action:   update,
		args: []string{
			"password",
			"-id", x.account.Id,
			"-name", x.account.Name,
			"-description", x.account.Description,
			"-format", "json"},
	}
	x.account = caseRunner(updateCase, x.account, t).(*accounts.Account)
	return nil
}

func (x *testAccount) delete(t *testing.T) error {
	deleteCase := testCase{
		cmd:      boundary,
		resource: acctCmd,
		action:   vDelete,
		args: []string{
			"-id", x.account.Id,
		},
	}

	x.account = caseRunner(deleteCase, x.account, t).(*accounts.Account)
	return nil
}

func TestAccount(t *testing.T) {
	var (
		acctName       = "test"
		acctDesc       = "testdescription"
		acctLogin      = "test"
		acctPass       = "testtest"
		acctDescUpdate = "testdescriptionupdate"

		ta = testAccount{
			account: &accounts.Account{
				Attributes: map[string]interface{}{
					"login_name": acctLogin,
					"password":   acctPass,
				},
				AuthMethodId: tcPAUM,
				Name:         acctName,
				Description:  acctDesc,
			},
		}
	)

	t.Run(fmt.Sprintf("%s %s %s", boundary, acctCmd, create), func(t *testing.T) {
		if err := ta.create(t, ""); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.account.Id, "account ID must not be empty")
	})

	createID := ta.account.Id

	t.Run(fmt.Sprintf("%s %s %s", boundary, acctCmd, read), func(t *testing.T) {
		if err := ta.read(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, createID, ta.account.Id, "create and read account ID must be equal")
		assert.Equal(t, ta.account.Name, acctName, "create name and read account name must be equal")
		assert.Equal(t, ta.account.Description, acctDesc, "create name and read account description must be equal")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, acctCmd, "login"), func(t *testing.T) {
		assert.NotEmpty(t, login(t, acctLogin, acctPass, tcPAUM), "must be able to login to account upon creation")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, acctCmd, update), func(t *testing.T) {
		ta.account.Description = acctDescUpdate
		if err := ta.update(t); err != nil {
			t.Error(err)
		}
		assert.Equal(t, ta.account.Description, acctDescUpdate, "account description must be updated")
	})

	t.Run(fmt.Sprintf("%s %s %s", boundary, acctCmd, vDelete), func(t *testing.T) {
		if err := ta.delete(t); err != nil {
			t.Error(err)
		}
		assert.NotEmpty(t, ta.account.Id, "account ID must not be empty on delete")
	})
}
