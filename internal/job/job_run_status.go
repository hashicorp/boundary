package job

const (
	// Running represents that the job run is actively running on a server
	Running = "running"

	// Completed represents that the job run has successfully finished
	Completed = "completed"

	// Failed represent that the job run had an error during execution
	Failed = "failed"

	// Interrupted represents that the job run was interrupted by a server
	// other than the server running the job.
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
