package models

import (
	"context"
	"fmt"
	"io"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/list"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type modelFactory struct {
	name           string
	modelFactoryFn messages.ModelFactoryFn
}

func (m modelFactory) FilterValue() string {
	return m.name
}

type listOption func(l *list.Model)

type modelFactoryList struct {
	*base.Command
	ctx           context.Context
	previousModel tea.Model
	commands      list.Model
	help          help.Model
	bindings      []key.Binding
}

func newModelFactoryList(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int, title string, modelFactories []modelFactory, opts ...listOption) tea.Model {
	var items []list.Item
	for _, modelFactory := range modelFactories {
		items = append(items, modelFactory)
	}
	l := list.New(items, itemDelegate{}, width, height)
	l.Title = title
	l.SetShowStatusBar(false)
	l.SetShowHelp(false)
	l.Styles.Title.UnsetBackground()
	bindings := []key.Binding{
		l.KeyMap.CursorUp,
		l.KeyMap.CursorDown,
		l.KeyMap.Filter,
	}
	if previousModel != nil {
		bindings = append(bindings, key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")))
		l.KeyMap.Quit.SetEnabled(false)
	} else {
		bindings = append(bindings, key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "quit")))
		l.KeyMap.Quit.SetKeys("esc")
	}
	for _, opt := range opts {
		opt(&l)
	}
	hp := help.New()
	hp.Width = width
	return modelFactoryList{
		Command:       cmd,
		ctx:           ctx,
		previousModel: previousModel,
		commands:      l,
		bindings:      bindings,
		help:          hp,
	}
}

func (m modelFactoryList) Init() tea.Cmd {
	return nil
}

func (m modelFactoryList) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.commands.SetWidth(msg.Width)
		m.commands.SetHeight(msg.Height - 6) // ?? Necessary for some reason
		m.help.Width = msg.Width
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEscape:
			if m.previousModel != nil {
				return m, func() tea.Msg {
					return messages.DisplayModelMsg{
						ModelFactoryFn: func(_ context.Context, _ *base.Command, _ tea.Model, _, _ int) tea.Model {
							return m.previousModel
						},
					}
				}
			}
		case tea.KeyEnter:
			newChild, ok := m.commands.SelectedItem().(modelFactory)
			if !ok {
				return m, tea.Sequence(tea.Println("selected item was not a model factory"), tea.Quit)
			}
			return m, func() tea.Msg {
				return messages.DisplayModelMsg{
					ModelFactoryFn: newChild.modelFactoryFn,
				}
			}
		}
	}
	var cmd tea.Cmd
	m.commands, cmd = m.commands.Update(msg)
	return m, cmd
}

func (m modelFactoryList) View() string {
	return lipgloss.JoinVertical(lipgloss.Center, m.commands.View(), m.help.ShortHelpView(m.bindings))
}

type itemDelegate struct{}

func (d itemDelegate) Height() int                             { return 1 }
func (d itemDelegate) Spacing() int                            { return 0 }
func (d itemDelegate) Update(_ tea.Msg, _ *list.Model) tea.Cmd { return nil }

func (d itemDelegate) Render(w io.Writer, m list.Model, index int, listItem list.Item) {
	if index == m.Index() {
		fmt.Fprint(w, lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#000000")).Foreground(lipgloss.Color("#ffffff")).Render(listItem.FilterValue()))
	} else {
		fmt.Fprint(w, listItem.FilterValue())
	}
}
