// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1


package credential

import (
	"testing"

	"github.com/hashicorp/boundary/internal/util"
	"github.com/hashicorp/boundary/internal/util/template"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_GetOpts(t *testing.T) {
	t.Parallel()
	t.Run("WithTemplateData", func(t *testing.T) {
		opts := getDefaultOptions()
		assert.Empty(t, opts.WithTemplateData)
		opts, err := GetOpts(WithTemplateData(template.Data{User: template.User{Id: util.Pointer("foo")}}))
		require.NoError(t, err)
		assert.Equal(t, "foo", *opts.WithTemplateData.User.Id)
	})
}
