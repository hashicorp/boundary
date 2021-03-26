package job

type RunStatus string

const (
	Running     RunStatus = "running"
	Completed   RunStatus = "completed"
	Failed      RunStatus = "failed"
	Interrupted RunStatus = "interrupted"
)

func (s RunStatus) IsValid() bool {
	switch s {
	case Running, Completed, Failed, Interrupted:
		return true
	}
	return false
}
