package sentinel

const (
	Start = '\ufffe'
	End   = '\uffff'
)

// Is returns true if s is a valid sentinel.
func Is(s string) bool {
	// A valid sentinel must be at least 6 bytes in len 3 bytes for '\ufffe' and 3
	// bytes for '\uffff'.
	if len(s) < 6 {
		return false
	}
	sr := []rune(s)
	if sr[0] == Start && sr[len(sr)-1] == End {
		return true
	}
	return false
}
