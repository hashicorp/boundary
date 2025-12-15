// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package action_test

import (
	"errors"
	"testing"

	"github.com/hashicorp/boundary/internal/types/action"
	"github.com/hashicorp/boundary/internal/types/resource"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegisterResource(t *testing.T) {
	t.Run("Pancis", func(t *testing.T) {
		// Ensure the resource is not registered yet
		_, err := action.ActionSetForResource(resource.Session)
		require.EqualError(t, err, "resource not found: session")

		// Now register the resource
		action.RegisterResource(resource.Session, action.NewActionSet(action.Read, action.Create), action.NewActionSet(action.List))
		got, err := action.ActionSetForResource(resource.Session)
		require.NoError(t, err)
		assert.Equal(t, action.NewActionSet(action.Read, action.Create, action.List), got)

		// Attempting to register the same resource again should panic
		require.Panics(
			t,
			func() {
				action.RegisterResource(resource.Session, action.NewActionSet(action.Update, action.Read, action.Create), action.NewActionSet(action.List))
			},
		)
	})

	// Run these after the Pancis test rely on resource.Session already being registered.
	t.Run("ActionSetForResource", func(t *testing.T) {
		cases := []struct {
			name    string
			res     resource.Type
			want    action.ActionSet
			wantErr error
		}{
			{
				"NotRegistered",
				resource.Target,
				nil,
				errors.New("resource not found: target"),
			},
			{
				"Registered",
				resource.Session,
				action.NewActionSet(action.Read, action.Create, action.List),
				nil,
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				got, err := action.ActionSetForResource(tc.res)
				if tc.wantErr != nil {
					require.EqualError(t, err, tc.wantErr.Error())
					return
				}

				require.NoError(t, err)
				assert.Equal(t, tc.want, got)
			})
		}
	})
}
