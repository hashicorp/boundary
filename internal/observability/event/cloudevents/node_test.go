package node

import (
	"net/url"
	"testing"

	"github.com/hashicorp/eventlogger/formatter_filters/cloudevents"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewFilterNode(t *testing.T) {
	t.Parallel()
	testSource, err := url.Parse("https://localhost:9200")
	require.NoError(t, err)
	tests := []struct {
		name            string
		source          *url.URL
		format          cloudevents.Format
		opt             []Option
		wantErr         bool
		wantIsError     error
		wantErrContains string
		wantAllow       []string
		wantDeny        []string
	}{
		{
			name:   "no-opts",
			source: testSource,
			format: cloudevents.FormatJSON,
		},
		{
			name:   "bad-allow-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithAllow("foo=;22", "foo==bar"),
			},
			wantErr:         true,
			wantErrContains: "invalid allow filter 'foo=;22'",
		},
		{
			name:   "bad-deny-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithDeny("foo=;22", "foo==bar"),
			},
			wantErr:         true,
			wantErrContains: "invalid deny filter 'foo=;22'",
		},
		{
			name:   "empty-allow-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithAllow(""),
			},
			wantErr:         true,
			wantErrContains: "missing filter",
		},
		{
			name:   "empty-deny-filter",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithDeny(""),
			},
			wantErr:         true,
			wantErrContains: "missing filter",
		},
		{
			name:   "empty-source",
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithAllow("alice==friend", "bob==friend"),
				WithDeny("eve==acquaintance", "fido!=dog"),
			},
			wantErr:         true,
			wantErrContains: "missing source",
		},
		{
			name:   "bad-format",
			source: testSource,
			format: "invalid-format",
			opt: []Option{
				WithAllow("alice==friend", "bob==friend"),
				WithDeny("eve==acquaintance", "fido!=dog"),
			},
			wantErr:         true,
			wantErrContains: "invalid format",
		},
		{
			name:   "valid-filters",
			source: testSource,
			format: cloudevents.FormatJSON,
			opt: []Option{
				WithAllow("alice==friend", "bob==friend"),
				WithDeny("eve==acquaintance", "fido!=dog"),
			},
			wantAllow: []string{"alice==friend", "bob==friend"},
			wantDeny:  []string{"eve==acquaintance", "fido!=dog"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			got, err := New(tt.source, tt.format, tt.opt...)
			if tt.wantErr {
				require.Error(err)
				assert.Nil(got)
				if tt.wantIsError != nil {
					assert.ErrorIs(err, tt.wantIsError)
				}
				if tt.wantErrContains != "" {
					assert.Contains(err.Error(), tt.wantErrContains)
				}
				return
			}
			require.NoError(err)
			assert.NotNil(got)
			assert.Len(got.allow, len(tt.wantAllow))
			for _, f := range got.allow {
				assert.Contains(tt.wantAllow, f.raw)
			}
			assert.Len(got.deny, len(tt.wantDeny))
			for _, f := range got.deny {
				assert.Contains(tt.wantDeny, f.raw)
			}

		})
	}
}
