package recovery

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/hashicorp/boundary/internal/db"
	"github.com/hashicorp/go-uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRecoveryTokens(t *testing.T) {
	ctx := context.Background()
	wrapper := db.TestWrapper(t)
	b, err := uuid.GenerateRandomBytes(nonceLength)
	require.NoError(t, err)
	assert.Len(t, b, 32)
	b64Nonce := base64.RawStdEncoding.EncodeToString(b)

	tests := []struct {
		name      string
		withTime  time.Time
		withNonce string
		wantErr   bool
	}{
		{
			name: "normal",
		},
		{
			name:      "zero time",
			withNonce: b64Nonce,
			wantErr:   true,
		},
		{
			name:      "future time",
			withNonce: b64Nonce,
			withTime:  time.Now().Add(5 * time.Minute),
			wantErr:   true,
		},
		{
			name:      "empty nonce",
			withNonce: string(""),
			withTime:  time.Now(),
			wantErr:   true,
		},
		{
			name:      "wrong nonce length",
			withNonce: base64.RawStdEncoding.EncodeToString(append(b, b...)),
			withTime:  time.Now(),
			wantErr:   true,
		},
		{
			name:      "bad nonce format",
			withNonce: string(b),
			withTime:  time.Now(),
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert, require := assert.New(t), require.New(t)
			if tt.withTime.IsZero() && tt.withNonce == "" {
				token, err := GenerateRecoveryToken(ctx, wrapper)
				require.NoError(err)
				assert.NotEmpty(token)
				info, err := ParseRecoveryToken(ctx, wrapper, token)
				require.NoError(err)
				assert.NotNil(info)
				return
			}

			token, err := formatToken(ctx, wrapper, &Info{
				Nonce:        tt.withNonce,
				CreationTime: tt.withTime,
			})
			require.NoError(err)
			assert.NotEmpty(token)
			info, err := ParseRecoveryToken(ctx, wrapper, token)
			if tt.wantErr {
				require.Error(err)
				return
			}
			require.NoError(err)
			assert.NotNil(info)
		})
	}
}
