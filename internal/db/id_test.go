package db

import (
	"strings"
	"testing"
)

func TestNewPublicId(t *testing.T) {
	type args struct {
		prefix string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
		wantLen int
	}{
		{
			name: "valid",
			args: args{
				prefix: "id",
			},
			wantErr: false,
			wantLen: 10 + len("id_"),
		},
		{
			name: "bad-prefix",
			args: args{
				prefix: "",
			},
			wantErr: true,
			wantLen: 0,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewPublicId(tt.args.prefix)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewPublicId() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && !strings.HasPrefix(got, tt.args.prefix+"_") {
				t.Errorf("NewPublicId() = %v, wanted it to start with %v", got, tt.args.prefix)
			}
			if len(got) != tt.wantLen {
				t.Errorf("NewPublicId() = %v, with len of %d and wanted len of %v", got, len(got), tt.wantLen)
			}

		})
	}
}
