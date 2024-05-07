// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package search

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/boundary/api/targets"
	daemoncmd "github.com/hashicorp/boundary/internal/clientcache/cmd/daemon"
	"github.com/hashicorp/boundary/internal/gen/controller/api"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textarea"
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
	p := tea.NewProgram(initModel(searchFn))
	if _, err := p.Run(); err != nil {
		return err
	}

	return nil
}

func initModel(searchFn func(input string) tea.Cmd) *model {
	// Response tables
	columns := []table.Column{
		{Title: "Id", Width: 12},
		{Title: "Type", Width: 6},
		{Title: "Name", Width: 50},
		{Title: "Description", Width: 50},
		{Title: "Scope Id", Width: 12},
	}
	tarTable := table.New(
		table.WithColumns(columns),
		table.WithFocused(false),
		table.WithHeight(20),
		table.WithFocused(false),
	)
	{
		s := table.DefaultStyles()
		s.Header = s.Header.
			BorderStyle(lipgloss.NormalBorder()).
			BorderForeground(lipgloss.Color("240")).
			BorderBottom(true).
			Bold(false)
		s.Selected = s.Selected.
			Foreground(lipgloss.Color("229")).
			Background(lipgloss.Color("57")).
			Bold(false)
		tarTable.SetStyles(s)
	}

	// Search text area
	ta := textarea.New()
	ta.Placeholder = "Search for something"
	ta.Focus()

	ta.Prompt = "> "
	ta.CharLimit = 280
	ta.SetWidth(30)
	ta.SetHeight(1)
	ta.FocusedStyle.CursorLine = lipgloss.NewStyle()
	ta.ShowLineNumbers = false

	return &model{
		searchInput: ta,
		resources: []string{
			"targets",
		},
		targetResults: tarTable,
		searchFn:      searchFn,
	}
}

const tuiSectionCount = 2

type model struct {
	// Section 0
	searchInput textarea.Model

	// Section 1
	resources       []string
	resourcesCursor int

	// Section 2
	targetResults table.Model

	sectionSelected int

	searchFn func(input string) tea.Cmd
	apiErr   *api.Error
}

func (m model) Init() tea.Cmd {
	return tea.Batch(textarea.Blink, m.searchFn(""), tea.EnterAltScreen)
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var (
		tiCmd     tea.Cmd
		searchCmd tea.Cmd
		tableCmd  tea.Cmd
	)

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC, tea.KeyEscape:
			return m, tea.Quit
		case tea.KeyEnter:
			if m.targetResults.Focused() {
				return m, tea.Printf("Authorizing Session for %s...\n", m.targetResults.SelectedRow()[0])
			}
		case tea.KeyTab:
			m.sectionSelected = (m.sectionSelected + 1) % tuiSectionCount
		default:
			switch {
			case m.searchInput.Focused():
				m.searchInput, tiCmd = m.searchInput.Update(msg)
				searchCmd = m.searchFn(m.searchInput.Value())
			case m.targetResults.Focused():
				m.targetResults, tableCmd = m.targetResults.Update(msg)
			}
		}
	case *resultsMsg:
		var rows []table.Row
		for _, t := range msg.targets {
			rows = append(rows, table.Row{t.Id, t.Type, t.Name, t.Description, t.ScopeId})
		}
		m.targetResults.SetRows(rows)
		m.targetResults, tableCmd = m.targetResults.Update(msg)
	case *api.Error:
		m.apiErr = msg
	case errMsg:
		// TODO: something
	}

	// Determine focus
	m.targetResults.Blur()
	m.searchInput.Blur()
	switch m.sectionSelected {
	case 0:
		m.searchInput.Focus()
	case 1:
		m.targetResults.Focus()
	}

	return m, tea.Batch(tiCmd, searchCmd, tableCmd)
}

func (m model) View() string {
	// The header
	s := "Boundary Target Search\n"
	s += fmt.Sprintf("%s\n", m.searchInput.View())
	if m.apiErr != nil {
		s += fmt.Sprintf("Error: %s\n", m.apiErr.Message)
	}
	s += m.targetResults.View()
	s += "\n"

	// The footer
	s += "\nPress Ctrl+C or ESC to quit. Press TAB to switch between search and results.\n"

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

			return &resultsMsg{
				targets: res.Targets,
			}
		}
	}
}
