package accountscmd

var extraPasswordActionsFlagsMap = map[string][]string{
	"create": {"login-name", "password"},
	"update": {"login-name"},
}

type extraPasswordCmdVars = struct {
	flagLoginName string
	flagPassword  string
}
