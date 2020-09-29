// +build integration

package e2e

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"testing"

	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/e2e/testcli"
	"github.com/hashicorp/boundary/testing/controller"
)

const (
	boundary      = "boundary"
	boundaryBuild = "BOUNDARY_BUILD"
)

var (
	create  = "create"
	read    = "read"
	update  = "update"
	vDelete = "delete"

	// override tcURL in TestMain()
	tcURL = os.Getenv("BOUNDARY_ADDR")

	tcLoginName = "admin"
	tcPassword  = "password"
	tcPAUM      = "ampw_1234567890"
	tcConfig    = []controller.Option{
		controller.WithDefaultAuthMethodId(tcPAUM),
		controller.WithDefaultLoginName(tcLoginName),
		controller.WithDefaultPassword(tcPassword),
	}
)

type testCase struct {
	cmd      string
	args     []string
	resource string
	action   string
}

func fatal(err error, cmd, stdout, stderr string, t *testing.T) {
	t.Fatalf("unexpected error running %s: %s\n  stdout: %s\n  stderr: %s\n", cmd, err.Error(), stdout, stderr)
}

func login(t *testing.T, user, password, authMethodID string) string {
	os.Setenv("BOUNDARY_ADDR", tcURL)

	c := testcli.Command(
		"docker", "run",
		"--network", "host",
		"-e", "BOUNDARY_ADDR="+tcURL,
		"-e", "BOUNDARY_TOKEN_NAME=none",

		boundary, "authenticate",
		"password",
		"-login-name", user,
		"-password", password,
		"-auth-method-id", authMethodID,
		"-format", "json")
	c.Run()

	if !c.Success() {
		fatal(c.Error(), "authenticate", c.Stdout(), c.Stderr(), t)
	}

	resp := &authtokens.AuthTokenReadResult{}
	if err := json.Unmarshal([]byte(c.Stdout()), resp); err != nil {
		fatal(err, "", "", "", t)
	}

	return resp.Item.Token
}

func caseRunner(tc testCase, resp interface{}, t *testing.T) interface{} {
	dockercmd := "docker"
	token := login(t, tcLoginName, tcPassword, tcPAUM)

	tc.args = append([]string{
		"run",
		"--network", "host",
		"-e", "BOUNDARY_ADDR=" + tcURL,
		"-e", "BOUNDARY_TOKEN_NAME=none",
		"-e", "BOUNDARY_TOKEN=" + token,
		tc.cmd, tc.resource, tc.action}, tc.args...)

	//	fmt.Printf("==> execute: %s %v\n", dockercmd, tc.args)

	c := testcli.Command(dockercmd, tc.args...)
	c.Run()

	if !c.Success() {
		fatal(c.Error(), tc.resource+" "+tc.action, c.Stdout(), c.Stderr(), t)
	}

	if tc.action != vDelete {
		if err := json.Unmarshal([]byte(c.Stdout()), resp); err != nil {
			fatal(err, "", "", "", t)
		}
	}

	return resp
}

func TestMain(m *testing.M) {
	if os.Getenv(boundaryBuild) != "" {
		if err := build(); err != nil {
			panic(err)
		}

		if err := createContainer(); err != nil {
			panic(err)
		}

		if err := copyToHost(); err != nil {
			panic(err)
		}

		if err := removeContainer(); err != nil {
			panic(err)
		}
	}

	// override the URL for boundary if BOUNDARY_ADDR is unset in env
	// by running the test controller interally
	if tcURL == "" {
		tc := controller.NewTestController(&testing.T{}, tcConfig...)
		defer tc.Shutdown()
		tcURL = tc.ApiAddrs()[0]
	}

	u, err := url.Parse(tcURL)
	if err != nil {
		panic(err)
	}

	hostA := strings.Split(u.Host, ":")
	host := hostA[0]
	port := hostA[1]

	// override with docker's DNS alias to the host localhost
	if host == "localhost" || host == "127.0.0.1" {
		u.Host = fmt.Sprintf("host.docker.internal:%s", port)
		tcURL = u.String()
	}

	os.Exit(m.Run())
}
