// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package bsr

import (
	"context"
	"fmt"
	"testing"

	"github.com/hashicorp/boundary/internal/bsr/internal/fstest"
	"github.com/hashicorp/boundary/internal/bsr/kms"
	"github.com/stretchr/testify/require"
)

func TestSyncBsrKeys(t *testing.T) {
	ctx := context.Background()

	keys, err := kms.CreateKeys(ctx, kms.TestWrapper(t), "session")
	require.NoError(t, err)
	f := &fstest.MemFS{}

	fc, err := f.New(ctx, fmt.Sprintf(bsrFileNameTemplate, "session-id"))
	require.NoError(t, err)

	c, err := newContainer(ctx, sessionContainer, fc, keys)
	require.NoError(t, err)
	require.NotNil(t, c)

	cases := []struct {
		name      string
		fname     string
		data      []byte
		expErr    bool
		expErrMsg string
	}{
		{
			name:      "no filename",
			data:      []byte("got no name"),
			expErr:    true,
			expErrMsg: "bsr.(container).syncBsrKey: missing file name invalid parameter",
		},
		{
			name:      "no data",
			fname:     "i have a name",
			expErr:    true,
			expErrMsg: "bsr.(container).syncBsrKey: missing data payload invalid parameter",
		},
		{
			name:  "success",
			fname: "i have a name",
			data:  []byte("payload coming thru"),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := c.syncBsrKey(ctx, tc.fname, tc.data)

			if tc.expErr {
				require.EqualError(t, err, tc.expErrMsg)
				return
			}
			require.NoError(t, err)
		})
	}
}
