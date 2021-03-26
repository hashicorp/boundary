package job

import "testing"

func TestRunStatus_IsValid(t *testing.T) {
	tests := []struct {
		name   string
		status RunStatus
		want   bool
	}{
		{
			name:   "running",
			status: Running,
			want:   true,
		},
		{
			name:   "completed",
			status: Completed,
			want:   true,
		},
		{
			name:   "failed",
			status: Failed,
			want:   true,
		},
		{
			name:   "interrupted",
			status: Interrupted,
			want:   true,
		},
		{
			name:   "invalid",
			status: "bad-status",
			want:   false,
		},
		{
			name:   "empty",
			status: "",
			want:   false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.status.IsValid(); got != tt.want {
				t.Errorf("IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}
