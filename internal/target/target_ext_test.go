// Copyright IBM Corp. 2020, 2025
// SPDX-License-Identifier: BUSL-1.1

package target_test

import (
	"testing"

	"github.com/hashicorp/boundary/internal/target"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTarget_SetTableName(t *testing.T) {
	t.Parallel()
	defaultTableName := target.TargetsViewDefaultTable
	tests := []struct {
		name      string
		setNameTo string
		want      string
	}{
		{
			name:      "new-name",
			setNameTo: "new-name",
			want:      "new-name",
		},
		{
			name:      "reset to default",
			setNameTo: "",
			want:      defaultTableName,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			def := target.AllocTargetView()
			require.Equal(defaultTableName, def.TableName())
			s := target.AllocTargetView()
			s.SetTableName(tt.setNameTo)
			assert.Equal(tt.want, s.TableName())
		})
	}
}
