// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package rate

import (
	"bytes"
	"sync"
)

var keyBuilderPool sync.Pool

type builder struct {
	bytes.Buffer
}

func join(parts ...string) string {
	var b *builder
	if v := keyBuilderPool.Get(); v != nil {
		b = v.(*builder)
		b.Reset()
	} else {
		b = &builder{}
	}
	defer keyBuilderPool.Put(b)

	end := len(parts) - 1
	for i, p := range parts {
		b.WriteString(p)
		if i != end {
			b.Write([]byte(":"))
		}
	}
	return b.String()
}
