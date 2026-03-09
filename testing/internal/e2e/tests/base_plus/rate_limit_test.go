// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package base_plus_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/hashicorp/boundary/testing/internal/e2e/boundary"
	"github.com/stretchr/testify/require"
)

// TestHttpRateLimit tests rate limiting when making HTTP API requests. When a
// request is rate limited, a HTTP 429 response is received. If a request is
// limited due to exceeding the quota limit, a HTTP 503 response is received.
// This test assumes that `api_rate_limit_max_quotas` in the config is set to 1
func TestHttpRateLimit(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)
	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := t.Context()
	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)

	// Authenticate over HTTP
	resAuth, err := boundary.AuthenticateHttp(t, ctx, bc.Address, bc.AuthMethodId, bc.AdminLoginName, bc.AdminLoginPassword)
	require.NoError(t, err)
	t.Cleanup(func() {
		resAuth.Body.Close()
	})
	require.Equal(t, http.StatusOK, resAuth.StatusCode)
	body, err := io.ReadAll(resAuth.Body)
	require.NoError(t, err)
	var r boundary.HttpResponseBody
	err = json.Unmarshal(body, &r)
	require.NoError(t, err)
	tokenAdmin := r.Attributes.Token

	// Make initial API request
	t.Log("Sending API requests until quota is hit...")
	requestURL := fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenAdmin))
	resInitial, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resInitial.Body.Close()
	})
	require.Equal(t, http.StatusOK, resInitial.StatusCode)
	body, err = io.ReadAll(resInitial.Body)
	require.NoError(t, err)
	require.NotEmpty(t, body)
	require.Contains(t, string(body), hostId)

	// Check that the limit from the policy matches the actual limit
	rateLimitPolicyHeader := resInitial.Header.Get("Ratelimit-Policy")
	require.NotEmpty(t, rateLimitPolicyHeader)
	policyLimit, policyPeriod, err := getRateLimitPolicyStat(resInitial.Header.Get("Ratelimit-Policy"), "auth-token")
	require.NoError(t, err)
	t.Log(rateLimitPolicyHeader)

	rateLimitHeader := resInitial.Header.Get("Ratelimit")
	require.NotEmpty(t, rateLimitHeader)
	t.Log(rateLimitHeader)
	limit, err := getRateLimitStat(rateLimitHeader, "limit")
	require.NoError(t, err)

	require.Equal(t, policyLimit, limit)

	// Make API requests until quota is hit
	quota, err := getRateLimitStat(rateLimitHeader, "remaining")
	require.NoError(t, err)
	for quota > 0 {
		requestURL = fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
		req, err = http.NewRequest(http.MethodGet, requestURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenAdmin))
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			res.Body.Close()
		})
		require.Equal(t, http.StatusOK, res.StatusCode)

		rateLimitHeader := res.Header.Get("Ratelimit")
		require.NotEmpty(t, rateLimitHeader)
		t.Log(rateLimitHeader)
		remaining, err := getRateLimitStat(rateLimitHeader, "remaining")
		require.NoError(t, err)
		require.Equal(t, quota-1, remaining, "Remaining quota did not decrease after sending API request")

		quota = remaining
	}

	// Do another request after the quota is exhausted
	// Verify that the request is not successful (HTTP 429: Too Many Requests)
	t.Log("Checking that next API request is rate limited...")
	requestURL = fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
	req, err = http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenAdmin))
	resAfter, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resAfter.Body.Close()
	})
	require.Equal(t, http.StatusTooManyRequests, resAfter.StatusCode)
	body, err = io.ReadAll(resAfter.Body)
	require.NoError(t, err)
	require.Empty(t, body)

	// Wait for "Retry-After" time
	retryAfterHeader := resAfter.Header.Get("Retry-After")
	require.NotEmpty(t, retryAfterHeader)
	retryAfter, err := strconv.Atoi(retryAfterHeader)
	require.NoError(t, err)
	t.Logf("Waiting for %d seconds to retry API request...", retryAfter)
	time.Sleep(time.Duration(retryAfter) * time.Second)

	// Do another request. Verify that request is successful
	t.Log("Retrying...")
	requestURL = fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
	req, err = http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenAdmin))
	resRetry, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resRetry.Body.Close()
	})
	require.Equal(t, http.StatusOK, resRetry.StatusCode)
	body, err = io.ReadAll(resRetry.Body)
	require.NoError(t, err)
	require.NotEmpty(t, body)
	require.Contains(t, string(body), hostId)

	t.Log("Successfully sent request after waiting")

	// Create a user
	acctName := "e2e-account"
	accountId, acctPassword, err := boundary.CreateAccountCli(t, ctx, bc.AuthMethodId, acctName)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", accountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	userId, err := boundary.CreateUserCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", userId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	err = boundary.SetAccountToUserCli(t, ctx, userId, accountId)
	require.NoError(t, err)
	roleId, err := boundary.CreateRoleCli(t, ctx, projectId)
	require.NoError(t, err)
	err = boundary.AddGrantToRoleCli(t, ctx, roleId, "ids=*;type=*;actions=*")
	require.NoError(t, err)
	err = boundary.AddPrincipalToRoleCli(t, ctx, roleId, userId)
	require.NoError(t, err)

	// Get auth token for second user
	resAuth2, err := boundary.AuthenticateHttp(t, ctx, bc.Address, bc.AuthMethodId, acctName, acctPassword)
	require.NoError(t, err)
	t.Cleanup(func() {
		resAuth2.Body.Close()
	})
	require.Equal(t, http.StatusOK, resAuth2.StatusCode)
	body, err = io.ReadAll(resAuth2.Body)
	require.NoError(t, err)
	err = json.Unmarshal(body, &r)
	require.NoError(t, err)
	tokenUser := r.Attributes.Token

	// Make request until quota is hit again using the first user
	t.Log("Sending API requests until quota is hit...")
	requestURL = fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
	req, err = http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenAdmin))
	resQuota, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resQuota.Body.Close()
	})
	require.Equal(t, http.StatusOK, resQuota.StatusCode)
	rateLimitHeader = resQuota.Header.Get("Ratelimit")
	require.NotEmpty(t, rateLimitHeader)
	t.Log(rateLimitHeader)
	quota, err = getRateLimitStat(rateLimitHeader, "remaining")
	require.NoError(t, err)

	for quota > 0 {
		requestURL = fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
		req, err := http.NewRequest(http.MethodGet, requestURL, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenAdmin))
		res, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		t.Cleanup(func() {
			res.Body.Close()
		})
		require.Equal(t, http.StatusOK, res.StatusCode)

		rateLimitHeader := res.Header.Get("Ratelimit")
		require.NotEmpty(t, rateLimitHeader)
		t.Log(rateLimitHeader)
		remaining, err := getRateLimitStat(rateLimitHeader, "remaining")
		require.NoError(t, err)
		require.Equal(t, quota-1, remaining, "Remaining quota did not decrease after sending API request")

		quota = remaining
	}

	// Confirm that a request from the second user results in a HTTP 503 due to
	// exceeding the quota limit
	t.Log("Checking that next API request is rejected...")
	requestURL = fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
	req, err = http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenUser))
	resReject, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resReject.Body.Close()
	})
	require.Equal(t, http.StatusServiceUnavailable, resReject.StatusCode)
	body, err = io.ReadAll(resReject.Body)
	require.NoError(t, err)
	require.Empty(t, body)

	// Wait for "Retry-After" time
	// Note: Not using the Retry-After time from an HTTP 503 response for now
	//
	// retryAfterHeader = res.Header.Get("Retry-After")
	// require.NotEmpty(t, retryAfterHeader)
	// retryAfter, err = strconv.Atoi(retryAfterHeader)
	// require.NoError(t, err)
	t.Logf("Waiting for %d seconds to retry API request...", policyPeriod+1)
	time.Sleep(time.Duration(policyPeriod+1) * time.Second)

	// Do another request. Verify that request is successful
	t.Log("Retrying...")
	requestURL = fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
	req, err = http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenUser))
	resSuccess, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resSuccess.Body.Close()
	})
	require.Equal(t, http.StatusOK, resSuccess.StatusCode)
	t.Log("Successfully sent request after waiting")

	time.Sleep(time.Duration(policyPeriod) * time.Second)
	t.Logf("Waiting for %d seconds for quote to expire...", policyPeriod)
}

// TestCliRateLimit tests rate limiting when using the boundary cli. When a
// request is rate limited, a 429 response is received and if a request is quota
// limited, a 503 response is received. If the BOUNDARY_MAX_RETRIES environment
// variable it set, it will instead auto-retry, automatically trying again after
// Retry-After seconds (from the response header)
func TestCliRateLimit(t *testing.T) {
	e2e.MaybeSkipTest(t)
	c, err := loadTestConfig()
	require.NoError(t, err)

	bc, err := boundary.LoadConfig()
	require.NoError(t, err)

	ctx := t.Context()

	boundary.AuthenticateAdminCli(t, ctx)
	orgId, err := boundary.CreateOrgCli(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary", e2e.WithArgs("scopes", "delete", "-id", orgId))
		require.NoError(t, output.Err, string(output.Stderr))
	})
	projectId, err := boundary.CreateProjectCli(t, ctx, orgId)
	require.NoError(t, err)
	hostCatalogId, err := boundary.CreateHostCatalogCli(t, ctx, projectId)
	require.NoError(t, err)
	hostId, err := boundary.CreateHostCli(t, ctx, hostCatalogId, c.TargetAddress)
	require.NoError(t, err)

	// Create a user
	acctName := "e2e-account"
	accountId, acctPassword, err := boundary.CreateAccountCli(t, ctx, bc.AuthMethodId, acctName)
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("accounts", "delete", "-id", accountId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	userId, err := boundary.CreateUserCli(t, ctx, "global")
	require.NoError(t, err)
	t.Cleanup(func() {
		ctx := context.Background()
		boundary.AuthenticateAdminCli(t, ctx)
		output := e2e.RunCommand(ctx, "boundary",
			e2e.WithArgs("users", "delete", "-id", userId),
		)
		require.NoError(t, output.Err, string(output.Stderr))
	})
	err = boundary.SetAccountToUserCli(t, ctx, userId, accountId)
	require.NoError(t, err)
	roleId, err := boundary.CreateRoleCli(t, ctx, projectId)
	require.NoError(t, err)
	err = boundary.AddGrantToRoleCli(t, ctx, roleId, "ids=*;type=*;actions=*")
	require.NoError(t, err)
	err = boundary.AddPrincipalToRoleCli(t, ctx, roleId, userId)
	require.NoError(t, err)

	// Authenticate over HTTP
	resAuth, err := boundary.AuthenticateHttp(t, ctx, bc.Address, bc.AuthMethodId, bc.AdminLoginName, bc.AdminLoginPassword)
	require.NoError(t, err)
	t.Cleanup(func() {
		resAuth.Body.Close()
	})
	require.Equal(t, http.StatusOK, resAuth.StatusCode)
	body, err := io.ReadAll(resAuth.Body)
	require.NoError(t, err)
	var r boundary.HttpResponseBody
	err = json.Unmarshal(body, &r)
	require.NoError(t, err)
	tokenAdmin := r.Attributes.Token

	// Make initial API request
	t.Log("Getting rate limit info...")
	requestURL := fmt.Sprintf("%s/v1/hosts/%s", bc.Address, hostId)
	req, err := http.NewRequest(http.MethodGet, requestURL, nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenAdmin))
	resInitial, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	t.Cleanup(func() {
		resInitial.Body.Close()
	})
	require.Equal(t, http.StatusOK, resInitial.StatusCode)

	rateLimitPolicyHeader := resInitial.Header.Get("Ratelimit-Policy")
	t.Log(rateLimitPolicyHeader)
	require.NotEmpty(t, rateLimitPolicyHeader)
	policyLimit, policyPeriod, err := getRateLimitPolicyStat(resInitial.Header.Get("Ratelimit-Policy"), "auth-token")
	require.NoError(t, err)

	rateLimitHeader := resInitial.Header.Get("Ratelimit")
	t.Log(rateLimitHeader)

	// Wait for ratelimit to reset
	t.Logf("Waiting for %d seconds to reset rate limit...", policyPeriod+1)
	time.Sleep(time.Duration(policyPeriod+1) * time.Second)

	// Run tests until rate limit is hit. Expect to see a HTTP 429 when rate limited
	t.Log("Sending multiple CLI requests to hit rate limit...")
	var output *e2e.CommandResult
	for i := 0; i <= policyLimit; i++ {
		output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("hosts", "read", "-id", hostId))
		t.Log(output.Duration)
		if output.Err != nil {
			break
		}
		require.NoError(t, output.Err, string(output.Stderr))
		require.Equal(t, 0, output.ExitCode)
	}
	require.Error(t, output.Err, string(output.Stderr))
	require.Equal(t, 1, output.ExitCode)
	require.Contains(t, string(output.Stderr), strconv.Itoa(http.StatusTooManyRequests))
	t.Log("Successfully observed a HTTP 429 response")

	// Log in as a second user and confirm you get a HTTP 503 response
	t.Log("Logging in as another user...")
	boundary.AuthenticateCli(t, ctx, bc.AuthMethodId, acctName, acctPassword)
	for i := 0; i <= policyLimit; i++ {
		output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("hosts", "read", "-id", hostId))
		t.Log(output.Duration)
		if output.Err != nil {
			break
		}
		require.NoError(t, output.Err, string(output.Stderr))
		require.Equal(t, 0, output.ExitCode)
	}
	require.Error(t, output.Err, string(output.Stderr))
	require.Equal(t, 1, output.ExitCode)
	require.Contains(t, string(output.Stderr), strconv.Itoa(http.StatusServiceUnavailable))
	t.Log("Successfully observed a HTTP 503 response")
	time.Sleep(time.Duration(policyPeriod) * time.Second)

	// Setting this environment variable sets CLI to use an auto-retry when rate
	// limited
	boundary.AuthenticateAdminCli(t, ctx)
	t.Log("Setting BOUNDARY_MAX_RETRIES environment variable...")
	os.Setenv("BOUNDARY_MAX_RETRIES", "2")
	t.Cleanup(func() {
		os.Unsetenv("BOUNDARY_MAX_RETRIES")
	})

	// Run tests until rate limit is hit. Expect to see the CLI auto-retry (the
	// command will take longer to return)
	t.Log("Sending multiple CLI requests to hit rate limit...")
	for i := 0; i <= policyLimit; i++ {
		output = e2e.RunCommand(ctx, "boundary", e2e.WithArgs("hosts", "read", "-id", hostId))
		t.Log(output.Duration)
		require.NoError(t, output.Err, string(output.Stderr))
		require.Equal(t, 0, output.ExitCode)
	}
	t.Log("Successfully auto-retried CLI request")
}

func getRateLimitStat(rateLimitHeader, stat string) (int, error) {
	ss := strings.Split(rateLimitHeader, ", ")
	for _, s := range ss {
		if strings.Contains(s, stat) {
			parts := strings.Split(s, "=")
			if len(parts) != 2 {
				return 0, fmt.Errorf("Expected length of 2: VALUE: %s", parts)
			}
			count, err := strconv.Atoi(parts[1])
			if err != nil {
				return 0, fmt.Errorf("Expected a number: VALUE: %s", parts[1])
			}

			return count, nil
		}
	}

	return 0, fmt.Errorf("Could not parse header, STAT: %s, HEADER: %s", stat, rateLimitHeader)
}

func getRateLimitPolicyStat(rateLimitPolicyHeader, stat string) (limit int, period int, err error) {
	ss := strings.Split(rateLimitPolicyHeader, ", ")
	for _, s := range ss {
		if strings.Contains(s, stat) {
			parts := strings.Split(s, ";")
			if len(parts) != 3 {
				return 0, 0, fmt.Errorf("Expected length of 3: VALUE: %s", parts)
			}
			limit, err := strconv.Atoi(parts[0])
			if err != nil {
				return 0, 0, fmt.Errorf("Expected a number: VALUE: %s", parts[0])
			}
			policyParts := strings.Split(parts[1], "=")
			if len(policyParts) != 2 {
				return 0, 0, fmt.Errorf("Expected length of 2: VALUE: %s", policyParts)
			}
			period, err := strconv.Atoi(policyParts[1])
			if err != nil {
				return 0, 0, fmt.Errorf("Expected a number: VALUE: %d", period)
			}
			return limit, period, nil
		}
	}

	return 0, 0, fmt.Errorf("Could not parse header, STAT: %s, HEADER: %s", stat, rateLimitPolicyHeader)
}
