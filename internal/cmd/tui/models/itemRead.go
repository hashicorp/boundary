package models

import (
	"context"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type ItemReader interface {
	Read(context.Context, *api.Client, string) tea.Msg
	Populate(tea.Msg, viewport.Model) (viewport.Model, tea.Cmd)
}

type ChildModel interface {
	Model(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model
	Binding() key.Binding
}

type readModel struct {
	*base.Command
	ctx           context.Context
	previousModel tea.Model
	itemId        string
	viewport      viewport.Model
	help          help.Model
	bindings      []key.Binding
	reader        ItemReader
	child         ChildModel
}

func newItemReadModel(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int, itemId string, reader ItemReader, child ChildModel) readModel {
	hp := help.New()
	hp.Width = width
	vp := viewport.New(width-3, height-1)
	rm := readModel{
		ctx:           ctx,
		previousModel: previousModel,
		itemId:        itemId,
		Command:       cmd,
		viewport:      vp,
		help:          hp,
		bindings: []key.Binding{
			vp.KeyMap.Up,
			vp.KeyMap.Down,
			key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		},
		reader: reader,
		child:  child,
	}
	if rm.child != nil {
		rm.bindings = append(rm.bindings, rm.child.Binding())
	}
	return rm
}

func (m readModel) Init() tea.Cmd {
	return func() tea.Msg {
		c, err := m.Command.Client()
		if err != nil {
			return err
		}
		return m.reader.Read(m.ctx, c, m.itemId)
	}
}

func (m readModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.viewport.Width = msg.Width - 9
		m.viewport.Height = msg.Height - 7
		m.help.Width = msg.Width
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEscape:
			return m, func() tea.Msg {
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(_ context.Context, _ *base.Command, _ tea.Model, _, _ int) tea.Model {
						return m.previousModel
					},
				}
			}
		}
		if m.child != nil {
			for _, key := range m.child.Binding().Keys() {
				if msg.String() == key {
					return m, func() tea.Msg {
						return messages.DisplayModelMsg{
							ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
								return m.child.Model(ctx, cmd, previousModel, width, height, m.itemId)
							},
						}
					}
				}
			}
		}
	}
	var popCmd tea.Cmd
	m.viewport, popCmd = m.reader.Populate(msg, m.viewport)
	var vCmd tea.Cmd
	m.viewport, vCmd = m.viewport.Update(msg)
	return m, tea.Batch(popCmd, vCmd)
}

func (m readModel) View() string {
	if m.viewport.TotalLineCount() == 0 {
		return "Loading..."
	}
	return lipgloss.JoinVertical(
		lipgloss.Center,
		lipgloss.Place(m.viewport.Width, m.viewport.Height, lipgloss.Left, lipgloss.Top,
			m.viewport.View(),
		),
		m.help.ShortHelpView(m.bindings),
	)
}
