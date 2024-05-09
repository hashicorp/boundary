// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package content

import "embed"

// DocsFS is an embed.FS that contains the complete Boundary docs.
//
//go:embed *
var DocsFS embed.FS
