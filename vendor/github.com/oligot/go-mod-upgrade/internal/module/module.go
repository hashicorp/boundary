package module

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/Masterminds/semver/v3"
	"github.com/fatih/color"
)

func padRight(str string, length int) string {
	if len(str) >= length {
		return str
	}
	return str + strings.Repeat(" ", length-len(str))
}

type Module struct {
	Name string
	From *semver.Version
	To   *semver.Version
}

func (mod *Module) FormatName(length int) string {
	c := color.New(color.FgWhite).SprintFunc()
	from := mod.From
	to := mod.To
	if from.Minor() != to.Minor() {
		c = color.New(color.FgYellow).SprintFunc()
	}
	if from.Patch() != to.Patch() {
		c = color.New(color.FgGreen).SprintFunc()
	}
	if from.Prerelease() != to.Prerelease() {
		c = color.New(color.FgRed).SprintFunc()
	}
	return c(padRight(mod.Name, length))
}

func (mod *Module) FormatFrom(length int) string {
	c := color.New(color.FgBlue).SprintFunc()
	return c(padRight(mod.From.String(), length))
}

func (mod *Module) FormatTo() string {
	green := color.New(color.FgGreen).SprintFunc()
	var buf bytes.Buffer
	from := mod.From
	to := mod.To
	same := true
	fmt.Fprintf(&buf, "%d.", to.Major())
	if from.Minor() == to.Minor() {
		fmt.Fprintf(&buf, "%d.", to.Minor())
	} else {
		fmt.Fprintf(&buf, "%s%s", green(to.Minor()), green("."))
		same = false
	}
	if from.Patch() == to.Patch() && same {
		fmt.Fprintf(&buf, "%d", to.Patch())
	} else {
		fmt.Fprintf(&buf, "%s", green(to.Patch()))
		same = false
	}
	if to.Prerelease() != "" {
		if from.Prerelease() == to.Prerelease() && same {
			fmt.Fprintf(&buf, "-%s", to.Prerelease())
		} else {
			fmt.Fprintf(&buf, "-%s", green(to.Prerelease()))
		}
	}
	if to.Metadata() != "" {
		fmt.Fprintf(&buf, "%s%s", green("+"), green(to.Metadata()))
	}
	return buf.String()
}
