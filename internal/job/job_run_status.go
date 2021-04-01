package job

const (
	Running     = "running"
	Completed   = "completed"
	Failed      = "failed"
	Interrupted = "interrupted"
)

func isValidRunStatus(s string) bool {
	switch s {
	case Running, Completed, Failed, Interrupted:
		return true
	}
	return false
}

func isFinalRunStatus(s string) bool {
	switch s {
	case Completed, Failed, Interrupted:
		return true
	}
	return false
}
