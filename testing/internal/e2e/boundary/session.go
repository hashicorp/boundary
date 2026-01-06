// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

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

// WaitForSessionCli waits for sessions to appear in the session list and returns the most recent session
// information. If the WithExpectedSessionsCount option is provided, expects to find specified amount of sessions
// or only 1 otherwise.
func WaitForSessionCli(t testing.TB, ctx context.Context, projectId string, sessionOpts []SessionOption, e2eOpts ...e2e.Option) *sessions.Session {
	opts := getSessionOpts(sessionOpts...)

	var options []e2e.Option
	options = append(options,
		e2e.WithArgs("sessions", "list", "-scope-id", projectId, "-include-terminated", "-format", "json"),
	)
	options = append(options, e2eOpts...)

	t.Log("Waiting for session to appear...")
	var session *sessions.Session

	err := backoff.RetryNotify(
		func() error {
			// List sessions
			output := e2e.RunCommand(ctx, "boundary",
				options...,
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
			if sessionCount != opts.WithExpectedSessionsCount {
				return backoff.Permanent(fmt.Errorf("Unexpected number of sessions. Expected: %d, Actual: %d", opts.WithExpectedSessionsCount, sessionCount))
			}

			// Get the most recent session
			session = sessionListResult.Items[0]
			t.Logf("Created Session: %s", session.Id)
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

// WaitForSessionStatusCli reads the specified session and waits for its status to match the
// specified status
func WaitForSessionStatusCli(t testing.TB, ctx context.Context, sessionId string, status string) {
	t.Logf("Waiting for session to be %s...", status)
	err := backoff.RetryNotify(
		func() error {
			output := e2e.RunCommand(ctx, "boundary",
				e2e.WithArgs("sessions", "read", "-id", sessionId, "-format", "json"),
			)
			if output.Err != nil {
				return backoff.Permanent(errors.New(string(output.Stderr)))
			}

			var sessionReadResult sessions.SessionReadResult
			err := json.Unmarshal(output.Stdout, &sessionReadResult)
			if err != nil {
				return backoff.Permanent(err)
			}
			s := sessionReadResult.Item

			if s.Status != status {
				return fmt.Errorf("Waiting for session status... Expected: %s, Actual: %s",
					status,
					sessionReadResult.Item.Status,
				)
			}

			return nil
		},
		backoff.WithMaxRetries(backoff.NewConstantBackOff(3*time.Second), 5),
		func(err error, td time.Duration) {
			t.Logf("%s. Retrying...", err.Error())
		},
	)
	require.NoError(t, err)
}

// getSessionOpts iterates the inbound SessionOption and returns a struct
func getSessionOpts(opt ...SessionOption) sessionOptions {
	opts := sessionOptions{
		WithExpectedSessionsCount: 1,
	}
	for _, o := range opt {
		o(&opts)
	}
	return opts
}

// SessionOption represents how Options are passed as arguments
type SessionOption func(*sessionOptions)

// sessionOptions is a struct representing available options for sessions
type sessionOptions struct {
	WithExpectedSessionsCount int
}

// WithExpectedSessionsCount provides an option to expect specified amount of sessions
func WithExpectedSessionsCount(count int) SessionOption {
	return func(o *sessionOptions) {
		o.WithExpectedSessionsCount = count
	}
}
