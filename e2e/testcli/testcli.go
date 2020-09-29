// inspired by github.com/rendon/testcli
package testcli

import (
	"bytes"
	"errors"
	"io"
	"log"
	"os"
	"os/exec"
	"regexp"
	"strings"
)

// Cmd is typically constructed through the Command() call and provides state
// to the execution engine.
type Cmd struct {
	cmd       *exec.Cmd
	env       []string
	exitError error
	executed  bool
	stdout    string
	stderr    string
	stdin     io.Reader
}

// ErrUninitializedCmd is returned when members are accessed before a run, that
// can only be used after a command has been run.
var ErrUninitializedCmd = errors.New("You need to run this command first")
var pkgCmd = &Cmd{}

// Command constructs a *Cmd. It is passed the command name and arguments.
func Command(name string, arg ...string) *Cmd {
	return &Cmd{
		cmd: exec.Command(name, arg...),
	}
}

func (c *Cmd) validate() {
	if !c.executed {
		log.Fatal(ErrUninitializedCmd)
	}
}

// SetEnv overwrites the environment with the provided one. Otherwise, the
// parent environment will be supplied.
func (c *Cmd) SetEnv(env []string) {
	c.env = env
}

// SetStdin sets the stdin stream. It makes no attempt to determine if the
// command accepts anything over stdin.
func (c *Cmd) SetStdin(stdin io.Reader) {
	c.stdin = stdin
}

// Run runs the command.
func (c *Cmd) Run() {
	if c.stdin != nil {
		c.cmd.Stdin = c.stdin
	}

	if c.env != nil {
		c.cmd.Env = c.env
	} else {
		c.cmd.Env = os.Environ()
	}

	var outBuf bytes.Buffer
	c.cmd.Stdout = &outBuf

	var errBuf bytes.Buffer
	c.cmd.Stderr = &errBuf

	if err := c.cmd.Run(); err != nil {
		c.exitError = err
	}
	c.stdout = string(outBuf.Bytes())
	c.stderr = string(errBuf.Bytes())
	c.executed = true
}

// Run runs a command with name and arguments. After this, package-level
// functions will return the data about the last command run.
func Run(name string, arg ...string) {
	pkgCmd = Command(name, arg...)
	pkgCmd.Run()
}

// Error is the command's error, if any.
func (c *Cmd) Error() error {
	c.validate()
	return c.exitError
}

// Error is the command's error, if any.
func Error() error {
	return pkgCmd.Error()
}

// Stdout stream for the command
func (c *Cmd) Stdout() string {
	c.validate()
	return c.stdout
}

// Stdout stream for the command
func Stdout() string {
	return pkgCmd.Stdout()
}

// Stderr stream for the command
func (c *Cmd) Stderr() string {
	c.validate()
	return c.stderr
}

// Stderr stream for the command
func Stderr() string {
	return pkgCmd.Stderr()
}

// StdoutContains determines if command's STDOUT contains `str`, this operation
// is case insensitive.
func (c *Cmd) StdoutContains(str string) bool {
	c.validate()
	str = strings.ToLower(str)
	return strings.Contains(strings.ToLower(c.stdout), str)
}

// StdoutContains determines if command's STDOUT contains `str`, this operation
// is case insensitive.
func StdoutContains(str string) bool {
	return pkgCmd.StdoutContains(str)
}

// StderrContains determines if command's STDERR contains `str`, this operation
// is case insensitive.
func (c *Cmd) StderrContains(str string) bool {
	c.validate()
	str = strings.ToLower(str)
	return strings.Contains(strings.ToLower(c.stderr), str)
}

// StderrContains determines if command's STDERR contains `str`, this operation
// is case insensitive.
func StderrContains(str string) bool {
	return pkgCmd.StderrContains(str)
}

// Success is a boolean status which indicates if the program exited non-zero
// or not.
func (c *Cmd) Success() bool {
	c.validate()
	return c.exitError == nil
}

// Success is a boolean status which indicates if the program exited non-zero
// or not.
func Success() bool {
	return pkgCmd.Success()
}

// Failure is the inverse of Success().
func (c *Cmd) Failure() bool {
	c.validate()
	return c.exitError != nil
}

// Failure is the inverse of Success().
func Failure() bool {
	return pkgCmd.Failure()
}

// StdoutMatches compares a regex to the stdout produced by the command.
func (c *Cmd) StdoutMatches(regex string) bool {
	c.validate()
	re := regexp.MustCompile(regex)
	return re.MatchString(c.Stdout())
}

// StdoutMatches compares a regex to the stdout produced by the command.
func StdoutMatches(regex string) bool {
	return pkgCmd.StdoutMatches(regex)
}

// StderrMatches compares a regex to the stderr produced by the command.
func (c *Cmd) StderrMatches(regex string) bool {
	c.validate()
	re := regexp.MustCompile(regex)
	return re.MatchString(c.Stderr())
}

// StderrMatches compares a regex to the stderr produced by the command.
func StderrMatches(regex string) bool {
	return pkgCmd.StderrMatches(regex)
}
