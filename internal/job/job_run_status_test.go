package job

import "testing"

func TestRunStatus_isFinalRunStatus(t *testing.T) {
	tests := []struct {
		name   string
		status Status
		want   bool
	}{
		{
			name:   "running",
			status: Running,
			want:   false,
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
			if got := tt.status.isFinalRunStatus(); got != tt.want {
				t.Errorf("isFinalRunStatus() = %v, want %v", got, tt.want)
			}
		})
	}
}
