package models

import (
	"context"
	"math"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type ItemCreator interface {
	TypeName() string
	Form() []textinput.Model
	Create(context.Context, *api.Client, []textinput.Model) error
}

type createModel struct {
	*base.Command
	ctx           context.Context
	previousModel tea.Model
	creator       ItemCreator
	inputs        []textinput.Model
	help          help.Model
	bindings      []key.Binding
	height        int
}

func newItemCreateModel(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int, creator ItemCreator) createModel {
	hp := help.New()
	hp.Width = width
	cm := createModel{
		ctx:           ctx,
		previousModel: previousModel,
		Command:       cmd,
		creator:       creator,
		inputs:        creator.Form(),
		help:          hp,
		bindings: []key.Binding{
			key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		},
		height: height,
	}
	for i := range cm.inputs {
		cm.inputs[i].Blur()
		cm.inputs[i].Width = int(math.Min(float64(width)*0.5, 20))
	}
	if len(cm.inputs) > 0 {
		cm.inputs[0].Focus()
	}
	return cm
}

func (m createModel) Init() tea.Cmd {
	return nil
}

func (m createModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		for i := range m.inputs {
			m.inputs[i].Width = int(math.Min(float64(msg.Width)*0.5, 20))
		}
		m.help.Width = msg.Width
	case tea.KeyMsg:
		switch msg.String() {
		case tea.KeyEscape.String():
			return m, func() tea.Msg {
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(_ context.Context, _ *base.Command, _ tea.Model, _, _ int) tea.Model {
						return m.previousModel
					},
				}
			}
		case tea.KeyEnter.String():
			if len(m.inputs) == 0 || m.inputs[len(m.inputs)-1].Focused() {
				return m, func() tea.Msg {
					cli, err := m.Command.Client()
					if err != nil {
						return err
					}
					if err := m.creator.Create(m.ctx, cli, m.inputs); err != nil {
						return err
					}
					return messages.DisplayModelMsg{
						ModelFactoryFn: func(_ context.Context, _ *base.Command, _ tea.Model, _, _ int) tea.Model {
							return m.previousModel
						},
					}
				}
			}
			for i, field := range m.inputs {
				if !field.Focused() {
					continue
				}
				m.inputs[i].Blur()
				m.inputs[i+1].Focus()
				break
			}
		case tea.KeyDown.String(), tea.KeyTab.String():
			if len(m.inputs) != 0 && !m.inputs[len(m.inputs)-1].Focused() {
				for i, field := range m.inputs {
					if !field.Focused() {
						continue
					}
					m.inputs[i].Blur()
					m.inputs[i+1].Focus()
					break
				}
			}
		case tea.KeyUp.String(), tea.KeyShiftTab.String():
			if len(m.inputs) != 0 && !m.inputs[0].Focused() {
				for i, field := range m.inputs {
					if !field.Focused() {
						continue
					}
					m.inputs[i].Blur()
					m.inputs[i-1].Focus()
					break
				}
			}

		}
	}
	var updates []tea.Cmd
	for i, field := range m.inputs {
		var cmd tea.Cmd
		m.inputs[i], cmd = field.Update(msg)
		updates = append(updates, cmd)
	}
	return m, tea.Batch(updates...)
}

func (m createModel) View() string {
	s := []string{
		"Create a new " + m.creator.TypeName() + "\n",
	}
	for _, field := range m.inputs {
		// Set field width (+1 for cursor)
		s = append(s, lipgloss.NewStyle().Width(field.Width+lipgloss.Width(field.Prompt)+1).Render(field.View()))
	}
	return lipgloss.JoinVertical(
		lipgloss.Center,
		lipgloss.PlaceVertical(m.height-2, lipgloss.Center, lipgloss.JoinVertical(lipgloss.Left, s...)),
		m.help.ShortHelpView(m.bindings),
	)
}
