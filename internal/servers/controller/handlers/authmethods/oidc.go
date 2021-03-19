package authmethods

type oidcState uint

const (
	unknownState oidcState = iota
	inactiveState
	privateState
	publicState
)

var oidcStateMap = map[string]oidcState{
	inactiveState.String(): inactiveState,
	privateState.String():  privateState,
	publicState.String():   publicState,
}

func (o oidcState) String() string {
	return [...]string{
		"unknown",
		"inactive",
		"active-private",
		"active-public",
	}[o]
}
