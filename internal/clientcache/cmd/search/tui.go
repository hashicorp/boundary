// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/hashicorp/boundary/api/aliases"
	"github.com/hashicorp/boundary/api/targets"
	daemoncmd "github.com/hashicorp/boundary/internal/clientcache/cmd/daemon"
	"github.com/hashicorp/boundary/internal/cmd/commands/targetscmd"
	"github.com/hashicorp/boundary/internal/gen/controller/api"

	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textarea"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func (c *SearchCommand) tui(ctx context.Context) error {
	cl, err := c.Client()
	if err != nil {
		return err
	}
	t := cl.Token()
	if t == "" {
		return fmt.Errorf("Auth Token selected for searching is empty.")
	}
	tSlice := strings.SplitN(t, "_", 3)
	if len(tSlice) != 3 {
		return fmt.Errorf("Auth Token selected for searching is in an unexpected format.")
	}
	dotPath, err := daemoncmd.DefaultDotDirectory(ctx)
	if err != nil {
		return err
	}

	searchFn := searchFn(strings.Join(tSlice[:2], "_"), dotPath)
	m := initModel(searchFn)
	p := tea.NewProgram(m, tea.WithMouseCellMotion(), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}

	if m.err != nil {
		return m.err
	}
	if m.selectedTargetId != "" {
		if err := connectFn(m.selectedTargetId, m.selectedConnectSubCmd); err != nil {
			return err
		}
	}

	return nil
}

func initModel(searchFn func(input string) tea.Cmd) *model {
	return &model{
		searchInput: initSearchInput(),
		resources: []string{
			"targets",
		},
		targetTable: initTargetTable(),
		searchFn:    searchFn,
		detailsView: initDetailsView(),
	}
}

func initSearchInput() textarea.Model {
	focusedBorderStyle := lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(lipgloss.Color("#db2114"))

	blurredBorderStyle := lipgloss.NewStyle().
		Border(lipgloss.HiddenBorder())

	ta := textarea.New()
	ta.Placeholder = "Type in your search..."
	ta.Focus()

	ta.Prompt = "> "
	ta.CharLimit = 280
	ta.SetWidth(90)
	ta.SetHeight(1)
	ta.FocusedStyle.Base = focusedBorderStyle
	ta.BlurredStyle.Base = blurredBorderStyle
	ta.ShowLineNumbers = false
	return ta
}

func initTargetTable() table.Model {
	columns := []table.Column{
		{Title: "Name", Width: 40},
		{Title: "Description", Width: 50},
		{Title: "Type", Width: 6},
		{Title: "Aliases", Width: 20},
	}
	tarTable := table.New(
		table.WithColumns(columns),
		table.WithFocused(false),
		table.WithHeight(20),
		table.WithFocused(false),
		table.WithKeyMap(table.KeyMap{
			LineUp: key.NewBinding(
				key.WithKeys("up"),
				key.WithHelp("↑", "up"),
			),
			LineDown: key.NewBinding(
				key.WithKeys("down"),
				key.WithHelp("↓", "down"),
			),
			HalfPageUp: key.NewBinding(
				key.WithKeys("pgup"),
				key.WithHelp("pgup", "½ page up"),
			),
			HalfPageDown: key.NewBinding(
				key.WithKeys("pgdown"),
				key.WithHelp("pgdn", "½ page down"),
			),
		}),
	)
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = tableSelectionBlurStyle
	tarTable.SetStyles(s)
	return tarTable
}

var (
	detailsFocusedStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#db2114")).
				PaddingRight(2)

	detailsBlurStyle = lipgloss.NewStyle().
				BorderStyle(lipgloss.RoundedBorder()).
				BorderForeground(lipgloss.Color("#222222")).
				PaddingRight(2)

	tableSelectionFocusStyle = table.DefaultStyles().Selected.
					Foreground(lipgloss.Color("#ffffff")).
					Background(lipgloss.Color("#db2114")).
					Bold(false)

	tableSelectionBlurStyle = table.DefaultStyles().Selected.
				Foreground(lipgloss.Color("#ebe6e6")).
				Background(lipgloss.Color("#222222")).
				Bold(false)
)

const detailsWidth = 118

func initDetailsView() viewport.Model {
	vp := viewport.New(detailsWidth, 20)
	vp.Style = detailsBlurStyle
	vp.MouseWheelEnabled = true
	vp.KeyMap = viewport.KeyMap{
		Up: key.NewBinding(
			key.WithKeys("up"),
			key.WithHelp("↑", "up"),
		),
		Down: key.NewBinding(
			key.WithKeys("down"),
			key.WithHelp("↓", "down"),
		),
		HalfPageUp: key.NewBinding(
			key.WithKeys("pgup"),
			key.WithHelp("pgup", "½ page up"),
		),
		HalfPageDown: key.NewBinding(
			key.WithKeys("pgdown"),
			key.WithHelp("pgdn", "½ page down"),
		),
	}

	vp.SetContent("")
	return vp
}

const tuiSectionCount = 3

type model struct {
	log string

	selectedTargetId      string
	selectedConnectSubCmd string

	// Section 0
	searchInput textarea.Model

	// Section 1
	resources []string

	// Section 2
	targetTable   table.Model
	targetResults []*targets.Target

	detailsView viewport.Model

	sectionSelected int

	searchFn func(input string) tea.Cmd
	apiErr   *api.Error
	err      error
}

func (m *model) Init() tea.Cmd {
	return tea.Batch(textarea.Blink, m.searchFn("")) //, tea.EnterAltScreen)
}

func (m *model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		searchCmd tea.Cmd
		tableCmd  tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEscape:
			return m, tea.Quit
		}
		if cmd := m.updateExecDetection(msg); cmd != nil {
			return m, cmd
		}
		// Process the input
		m.updateSectionFocus(msg)
		searchCmd = m.updateSearch(msg)
		tableCmd = m.updateTableNavigation(msg)
		m.updateDetailsView()
	case *resultsMsg:
		m.targetResults = msg.targets
		var rows []table.Row
		for _, t := range msg.targets {
			aliasValue := ""
			if len(t.Aliases) > 0 {
				aliasValue = t.Aliases[0].Value
			}
			rows = append(rows, table.Row{t.Name, t.Description, t.Type, aliasValue})
		}
		m.targetTable.SetRows(rows)
		m.targetTable, tableCmd = m.targetTable.Update(msg)

	case *api.Error:
		m.apiErr = msg
	case errMsg:
		// TODO: something
	}
	detailsCmd := m.updateDetailsPaging(msg)

	return m, tea.Batch(searchCmd, tableCmd, detailsCmd)
}

func (m *model) updateDetailsView() tea.Cmd {
	if !m.targetTable.Focused() || m.targetTable.SelectedRow() == nil {
		return nil
	}
	idx := m.targetTable.Cursor()
	if len(m.targetResults) <= idx {
		return nil
	}
	tar := m.targetResults[idx]
	m.detailsView.SetContent(targetscmd.PrintItemTable(tar))
	return nil
}

func (m *model) updateDetailsPaging(msg tea.Msg) tea.Cmd {
	if m.targetTable.Focused() || m.searchInput.Focused() {
		return nil
	}

	// The details is selected! Allow scrolling.
	var cmd tea.Cmd
	m.detailsView, cmd = m.detailsView.Update(msg)
	return cmd
}

func (m *model) updateSearch(msg tea.Msg) tea.Cmd {
	if !m.searchInput.Focused() {
		return nil
	}
	var inputCmd tea.Cmd
	m.searchInput, inputCmd = m.searchInput.Update(msg)
	searchCmd := m.searchFn(m.searchInput.Value())
	return tea.Batch(inputCmd, searchCmd)
}

func (m *model) updateExecDetection(msg tea.Msg) tea.Cmd {
	if !m.targetTable.Focused() {
		return nil
	}
	idx := m.targetTable.Cursor()
	if len(m.targetResults) <= idx {
		return nil
	}

	if m.targetTable.SelectedRow()[2] == "ssh" {
		m.selectedConnectSubCmd = "ssh"
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		if m.targetTable.SelectedRow()[2] == "ssh" {
			switch msg.String() {
			case tea.KeyEnter.String(), "s":
				m.selectedTargetId = m.targetResults[idx].Id
				m.selectedConnectSubCmd = "ssh"
				return tea.Quit
			}
		} else {
			switch msg.String() {
			case tea.KeyEnter.String():
				m.selectedTargetId = m.targetResults[idx].Id
				return tea.Quit
			case "s":
				m.selectedTargetId = m.targetResults[idx].Id
				m.selectedConnectSubCmd = "ssh"
				return tea.Quit
			case "h":
				m.selectedTargetId = m.targetResults[idx].Id
				m.selectedConnectSubCmd = "http"
				return tea.Quit
			case "p":
				m.selectedTargetId = m.targetResults[idx].Id
				m.selectedConnectSubCmd = "postgres"
				return tea.Quit
			case "r":
				m.selectedTargetId = m.targetResults[idx].Id
				m.selectedConnectSubCmd = "rdp"
				return tea.Quit
			}
		}
	}
	return nil
}

func (m *model) updateTableNavigation(msg tea.Msg) tea.Cmd {
	if !m.targetTable.Focused() {
		return nil
	}
	var tableCmd tea.Cmd
	m.targetTable, tableCmd = m.targetTable.Update(msg)
	return tableCmd
}

func (m *model) updateSectionFocus(msg tea.Msg) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyTab:
			m.sectionSelected = (m.sectionSelected + 1) % tuiSectionCount
		case tea.KeyShiftTab:
			m.sectionSelected = (m.sectionSelected + (tuiSectionCount - 1)) % tuiSectionCount
		default:
			return
		}
	default:
		return
	}

	tableStyle := table.DefaultStyles()
	tableStyle.Header = tableStyle.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	tableStyle.Selected = tableSelectionBlurStyle

	detailsStyle := detailsBlurStyle
	m.targetTable.Blur()
	m.searchInput.Blur()
	switch m.sectionSelected {
	case 0:
		m.searchInput.Focus()
	case 1:
		m.targetTable.Focus()
		tableStyle.Selected = tableSelectionFocusStyle
	case 2:
		detailsStyle = detailsFocusedStyle
	}
	m.detailsView.Style = detailsStyle
	m.targetTable.SetStyles(tableStyle)
}

func (m *model) View() string {
	// The header
	s := "Boundary Target Search\n"
	s += fmt.Sprintf("%s\n", m.searchInput.View())
	if m.apiErr != nil {
		s += fmt.Sprintf("Error: %s\n", m.apiErr.Message)
	}
	if m.err != nil {
		s += fmt.Sprintf("Error: %s\n", m.err)
	}
	if m.log != "" {
		s += fmt.Sprintf("Log: %s\n", m.err)
	}
	s += "\n"
	s += m.targetTable.View()
	s += "\n\n"

	// The footer
	if m.targetTable.Focused() && m.targetTable.SelectedRow() != nil {
		targetId := m.targetTable.SelectedRow()[0]
		switch m.targetTable.SelectedRow()[2] {
		case "ssh":
			s += fmt.Sprintf("Press ENTER or 's' to connect to %q.\n", targetId)
		default:
			s += fmt.Sprintf("Press ENTER to connect to %q. 's' with ssh, 'p' with postgres, 'h' with http, 'r' with rdp\n", targetId)
		}
	} else {
		s += "\n"
	}
	s += "\n"
	s += m.detailsView.View()
	s += "\n"
	s += "\nPress Ctrl+C or ESC to quit. Press TAB/Shift+TAB to switch between search and results.\n"

	// Send the UI for rendering
	return s
}

type errMsg struct{ err error }

func (e errMsg) Error() string { return e.err.Error() }

type resultsMsg struct {
	targets []*targets.Target
}

func searchFn(at, dotPath string) func(input string) tea.Cmd {
	return func(input string) tea.Cmd {
		return func() tea.Msg {
			var query []string
			query = append(query, fmt.Sprintf("id %% '%s'", input))
			query = append(query, fmt.Sprintf("type %% '%s'", input))
			query = append(query, fmt.Sprintf("name %% '%s'", input))
			query = append(query, fmt.Sprintf("description %% '%s'", input))
			query = append(query, fmt.Sprintf("address %% '%s'", input))
			query = append(query, fmt.Sprintf("scope_id %% '%s'", input))
			tf := filterBy{
				flagQuery:   strings.Join(query, " or "),
				resource:    "targets",
				authTokenId: at,
			}
			_, res, apiErr, err := search(context.TODO(), dotPath, tf)
			if err != nil {
				return errMsg{err: err}
			}

			if apiErr != nil {
				return apiErr
			}
			for _, t := range res.Targets {
				aliases, err := getAliasesFor(at, dotPath, t.Id)
				if err != nil {
					return errMsg{err: err}
				}
				for _, a := range aliases {
					t.Aliases = append(t.Aliases, &targets.Alias{Id: a.Id, Value: a.Value})
				}
			}

			return &resultsMsg{
				targets: res.Targets,
			}
		}
	}
}

func getAliasesFor(at, dotPath string, tid string) ([]*aliases.Alias, error) {
	var query []string
	query = append(query, fmt.Sprintf("destination_id %% '%s'", tid))
	tf := filterBy{
		flagQuery:   strings.Join(query, " or "),
		resource:    "resolvable-aliases",
		authTokenId: at,
	}
	_, res, apiErr, err := search(context.TODO(), dotPath, tf)
	if err != nil {
		return nil, err
	}

	if apiErr != nil {
		return nil, apiErr
	}
	return res.ResolvableAliases, nil
}

func connectFn(tid, subCmd string) error {
	cmdName, err := os.Executable()
	if err != nil {
		return err
	}

	args := []string{"connect"}
	if subCmd != "" {
		args = append(args, subCmd)
	}
	args = append(args, "-target-id", tid)

	c := exec.Command(cmdName, args...)
	c.Env = os.Environ()
	c.Stderr = os.Stderr
	c.Stdout = os.Stdout
	c.Stdin = os.Stdin
	return c.Run()
}
