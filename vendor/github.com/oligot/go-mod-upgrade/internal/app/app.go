package app

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/AlecAivazis/survey/v2"
	term "github.com/AlecAivazis/survey/v2/terminal"
	"github.com/Masterminds/semver/v3"
	"github.com/apex/log"
	"github.com/briandowns/spinner"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
	"golang.org/x/mod/modfile"

	"github.com/oligot/go-mod-upgrade/internal/module"
)

func max(x, y int) int {
	if x > y {
		return x
	}
	return y
}

// MultiSelect that doesn't show the answer
// It just reset the prompt and the answers are shown afterwards
type MultiSelect struct {
	survey.MultiSelect
}

func (m MultiSelect) Cleanup(config *survey.PromptConfig, val interface{}) error {
	return m.Render("", nil)
}

type AppEnv struct {
	Verbose  bool
	Force    bool
	PageSize int
	Hook     string
	Ignore   cli.StringSlice
}

func (app *AppEnv) Run() error {
	if app.Verbose {
		log.SetLevel(log.DebugLevel)
	}
	var paths []string
	gw, err := exec.Command("go", "env", "GOWORK").Output()
	if err != nil {
		return err
	}
	gowork := strings.TrimSpace(string(gw))
	if gowork == "" || gowork == "off" {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		paths = append(paths, cwd)
	} else {
		log.WithField("gowork", gowork).Info("Workspace mode")
		content, err := os.ReadFile(gowork)
		if err != nil {
			return err
		}
		work, err := modfile.ParseWork("go.work", content, nil)
		if err != nil {
			return err
		}
		for _, use := range work.Use {
			if use != nil {
				paths = append(paths, use.Path)
			}
		}
	}

	for _, path := range paths {
		cwd, err := os.Getwd()
		if err != nil {
			return err
		}
		dir := path
		if !filepath.IsAbs(path) {
			dir = filepath.Join(filepath.Dir(gowork), path)
		}
		log.WithField("dir", dir).Info("Using directory")
		if err := os.Chdir(dir); err != nil {
			return err
		}
		modules, err := discoverModules(app.Ignore.Value())
		if err != nil {
			return err
		}
		supported, err := toolsSupported()
		if err != nil {
			return err
		}
		log.WithFields(log.Fields{
			"supported": supported,
		}).Debug("Tool support")
		if supported {
			toolModules, err := discoverTools(app.Ignore.Value())
			if err != nil {
				return err
			}
			modules = append(modules, toolModules...)
		}
		if len(modules) > 0 {
			if app.Force {
				log.Debug("Update all modules in non-interactive mode...")
			} else {
				modules = choose(modules, app.PageSize)
			}
			update(modules, app.Hook)
		} else {
			fmt.Println("All modules are up to date")
		}
		if err := os.Chdir(cwd); err != nil {
			return err
		}
	}
	return nil
}

func discoverModules(ignoreNames []string) ([]module.Module, error) {
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	s.Suffix = " Discovering modules..."
	s.Start()

	args := []string{
		"list",
		"-u",
		"-mod=readonly",
		"-f",
		"'{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} -> {{.Update.Version}}{{end}}'",
		"-m",
		"all",
	}

	cmd := exec.Command("go", args...)
	// Disable Go workspace mode, otherwise this can cause trouble
	// See issue https://github.com/oligot/go-mod-upgrade/issues/35
	cmd.Env = append(os.Environ(), "GOWORK=off")
	list, err := cmd.Output()
	s.Stop()

	// Clear line
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))

	if err != nil {
		return nil, fmt.Errorf("Error running go command to discover modules: %w", err)
	}

	split := strings.Split(string(list), "\n")
	modules := []module.Module{}
	re := regexp.MustCompile(`'(.+): (.+) -> (.+)'`)
	for _, x := range split {
		if x != "''" && x != "" {
			matched := re.FindStringSubmatch(x)
			if len(matched) < 4 {
				return nil, fmt.Errorf("Couldn't parse module %s", x)
			}
			name, from, to := matched[1], matched[2], matched[3]
			log.WithFields(log.Fields{
				"name": name,
				"from": from,
				"to":   to,
			}).Debug("Found module")
			if shouldIgnore(name, from, to, ignoreNames) {
				continue
			}
			fromversion, err := semver.NewVersion(from)
			if err != nil {
				return nil, err
			}
			toversion, err := semver.NewVersion(to)
			if err != nil {
				return nil, err
			}
			d := module.Module{
				Name: name,
				From: fromversion,
				To:   toversion,
			}
			modules = append(modules, d)
		}
	}
	return modules, nil
}

func discoverTools(ignoreNames []string) ([]module.Module, error) {

	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond)
	if err := s.Color("yellow"); err != nil {
		return nil, err
	}
	s.Suffix = " Discovering tool modules..."
	s.Start()

	toolsArgs := []string{
		"list",
		"-f",
		"{{if .Module}}{{.Module.Path}} {{.Module.Version}}{{end}}",
		"tool",
	}
	cmd := exec.Command("go", toolsArgs...)
	cmd.Env = append(os.Environ(), "GOWORK=off")
	toolsOutput, err := cmd.Output()

	s.Stop()
	fmt.Printf("\r%s\r", strings.Repeat(" ", len(s.Suffix)+1))

	if err != nil {
		if strings.Contains(err.Error(), "matched no packages") {
			return []module.Module{}, nil
		}
		log.WithFields(log.Fields{
			"error": err,
			"args":  cmd.Args,
		}).Error("error listing tools")
		return nil, fmt.Errorf("error listing tools: %w", err)
	}

	var modules []module.Module
	tools := strings.Split(strings.TrimSpace(string(toolsOutput)), "\n")
	for _, tool := range tools {
		if tool == "" {
			continue
		}

		parts := strings.Fields(tool)
		if len(parts) == 1 {
			continue // local tool
		}
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid tool format: %s", tool)
		}
		toolPath, currentVersion := parts[0], parts[1]

		// Check for updates
		updateArgs := []string{
			"list",
			"-m",
			"-f",
			"{{if .Update}}{{.Update.Version}}{{end}}",
			"-u",
			toolPath,
		}
		updateCmd := exec.Command("go", updateArgs...)
		updateCmd.Env = append(os.Environ(), "GOWORK=off")
		if updateOutput, err := updateCmd.Output(); err == nil {
			newVersion := strings.TrimSpace(string(updateOutput))
			if newVersion != "" && newVersion != currentVersion {
				fromVersion, err := semver.NewVersion(currentVersion)
				if err != nil {
					return nil, fmt.Errorf("invalid tool version: %s -> %s: %w", toolPath, currentVersion, err)
				}
				toVersion, err := semver.NewVersion(newVersion)
				if err != nil {
					return nil, fmt.Errorf("invalid tool update version: %s -> %s: %w", toolPath, newVersion, err)
				}
				log.WithFields(log.Fields{
					"tool": toolPath,
					"from": currentVersion,
					"to":   newVersion,
				}).Debug("Found tool module update available")
				if shouldIgnore(toolPath, currentVersion, newVersion, ignoreNames) {
					continue
				}
				modules = append(modules, module.Module{
					Name: toolPath,
					From: fromVersion,
					To:   toVersion,
				})
			}
		}
	}

	return modules, nil
}

func toolsSupported() (bool, error) {
	gv, err := exec.Command("go", "version").Output()
	if err != nil {
		return false, err
	}

	version := strings.TrimSpace(string(gv))
	re := regexp.MustCompile(`go version go([\d\.]+)(rc.+)?`)
	matched := re.FindStringSubmatch(version)
	if len(matched) < 2 {
		return false, fmt.Errorf("Couldn't parse go version %s", version)
	}

	goversion, err := semver.NewVersion(matched[1])
	if err != nil {
		return false, err
	}
	log.WithFields(log.Fields{
		"major": goversion.Major(),
		"minor": goversion.Minor(),
	}).Debug("Go version")
	if goversion.Major() >= 1 && goversion.Minor() >= 24 {
		return true, nil
	}
	return false, nil
}

func shouldIgnore(name, from, to string, ignoreNames []string) bool {
	for _, ig := range ignoreNames {
		if strings.Contains(name, ig) {
			c := color.New(color.FgYellow).SprintFunc()
			log.WithFields(log.Fields{
				"name": name,
				"from": from,
				"to":   to,
			}).Debug(c("Ignore module"))
			return true
		}
	}
	return false
}

func choose(modules []module.Module, pageSize int) []module.Module {
	maxName := 0
	maxFrom := 0
	for _, x := range modules {
		maxName = max(maxName, len(x.Name))
		maxFrom = max(maxFrom, len(x.From.String()))
	}
	options := []string{}
	for _, x := range modules {
		from := x.FormatFrom(maxFrom)
		option := fmt.Sprintf("%s %s -> %s", x.FormatName(maxName), from, x.FormatTo())
		options = append(options, option)
	}
	prompt := &MultiSelect{
		survey.MultiSelect{
			Message:  "Choose which modules to update",
			Options:  options,
			PageSize: pageSize,
		},
	}
	choice := []int{}
	err := survey.AskOne(prompt, &choice)
	if err == term.InterruptErr {
		log.Info("Bye")
		os.Exit(0)
	} else if err != nil {
		log.WithError(err).Error("Choose failed")
		os.Exit(1)
	}
	updates := []module.Module{}
	for _, x := range choice {
		updates = append(updates, modules[x])
	}
	return updates
}

func update(modules []module.Module, hook string) {
	for _, x := range modules {
		fmt.Fprintf(color.Output, "Updating %s to version %s...\n", x.FormatName(len(x.Name)), x.FormatTo())
		out, err := exec.Command("go", "get", "-d", x.Name).CombinedOutput()
		if err != nil {
			log.WithFields(log.Fields{
				"error": err,
				"name":  x.Name,
				"out":   string(out),
			}).Error("Error while updating module")
		}
		if hook != "" {
			out, err := exec.Command(
				hook,
				x.Name,
				x.From.String(),
				x.To.String(),
			).CombinedOutput()
			if err != nil {
				log.WithFields(log.Fields{
					"error": err,
					"hook":  hook,
					"out":   string(out),
				}).Error("Error while executing hook")
				os.Exit(1)
			}
			log.Info(string(out))
		}
	}
}
