// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package boundary

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/hashicorp/boundary/api/sessions"
	"github.com/hashicorp/boundary/testing/internal/e2e"
	"github.com/stretchr/testify/require"
)

// WaitForSessionCli waits for a session to appear in the session list and returns the session
// information
func WaitForSessionCli(t testing.TB, ctx context.Context, projectId string) *sessions.Session {
	t.Log("Waiting for session to appear...")
	var session *sessions.Session
	err := backoff.RetryNotify(
		func() error {
			// List sessions
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("sessions", "list", "-scope-id", projectId, "-include-terminated", "-format", "json"),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}
			var sessionListResult sessions.SessionListResult
			err := json.Unmarshal(output.Stdout, &sessionListResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			// Check if there is one session
			sessionCount := len(sessionListResult.Items)
			if sessionCount == 0 {
				return errors.New("No items are appearing in the session list")
			}

			t.Logf("Found %d session(s)", sessionCount)
			if sessionCount != 1 {
				return backoff.Permanent(errors.New("Only one session was expected to be found"))
			}

			session = sessionListResult.Items[0]
			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)

	return session
}

// WaitForSessionToBeActiveCli waits for a session to appear in the session list and returns the
// session information once the session has an active status
func WaitForSessionToBeActiveCli(t testing.TB, ctx context.Context, projectId string) *sessions.Session {
	t.Log("Waiting for session to be active...")
	var session *sessions.Session
	err := backoff.RetryNotify(
		func() error {
			// List sessions
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("sessions", "list", "-scope-id", projectId, "-format", "json"),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}
			var sessionListResult sessions.SessionListResult
			err := json.Unmarshal(output.Stdout, &sessionListResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			// Check if there is one session
			sessionCount := len(sessionListResult.Items)
			if sessionCount == 0 {
				return errors.New("No items are appearing in the session list")
			}
			t.Logf("Found %d session(s)", sessionCount)
			if sessionCount != 1 {
				return backoff.Permanent(errors.New("Only one session was expected to be found"))
			}

			// Check if session is active
			session = sessionListResult.Items[0]
			output = e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("sessions", "read", "-id", session.Id, "-format", "json"),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var sessionReadResult sessions.SessionReadResult
			err = json.Unmarshal(output.Stdout, &sessionReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}

			if sessionReadResult.Item.Status != "active" {
				return errors.New(fmt.Sprintf("Waiting for session to be active... Expected: %s, Actual: %s",
					"active",
					sessionReadResult.Item.Status,
				))
			}

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)

	return session
}
