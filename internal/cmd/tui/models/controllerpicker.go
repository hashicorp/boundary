package models

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type controllerPicker struct {
	*base.Command
	ctx           context.Context
	previousModel tea.Model
	height        int
	name          textinput.Model
	address       textinput.Model
	help          help.Model
	bindings      []key.Binding
}

func NewControllerPicker(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) controllerPicker {
	name := textinput.New()
	name.Width = int(math.Min(float64(width)*0.5, 30))
	name.Prompt = "Controller name: "
	name.Placeholder = "production"
	name.Focus()
	address := textinput.New()
	address.Width = int(math.Min(float64(width)*0.5, 30))
	address.Prompt = "Boundary Controller URL: "
	address.Placeholder = "http://127.0.0.1:9200"
	hp := help.New()
	hp.Width = width
	return controllerPicker{
		ctx:           ctx,
		Command:       cmd,
		previousModel: previousModel,
		height:        height,
		name:          name,
		address:       address,
		help:          hp,
		bindings: []key.Binding{
			key.NewBinding(key.WithKeys(tea.KeyEscape.String()), key.WithHelp(tea.KeyEscape.String(), "back")),
		},
	}
}

func (m controllerPicker) Init() tea.Cmd {
	return nil
}

func (m controllerPicker) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.name.Width = int(math.Min(float64(msg.Width)*0.5, 20))
		m.address.Width = int(math.Min(float64(msg.Width)*0.5, 20))
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
		case tea.KeyEnter:
			if m.name.Focused() {
				m.name.Blur()
				m.address.Focus()
				break
			}
			if len(m.name.Value()) == 0 || len(m.address.Value()) == 0 {
				break
			}
			return m, func() tea.Msg {
				cli, err := m.Client()
				if err != nil {
					return err
				}
				_, err = authmethods.NewClient(cli).List(m.ctx, "global")
				if err != nil {
					if strings.Contains(err.Error(), "connect: connection refused") {
						err = fmt.Errorf("Couldn't find a Boundary controller running on %q. The error was:\n\n%w", cli.Addr(), err)
					}
					return err
				}
				return messages.AddControllerMsg{
					Name:    m.name.Value(),
					Address: m.address.Value(),
				}
			}
		case tea.KeyDown:
			if m.name.Focused() {
				m.name.Blur()
				m.address.Focus()
			}
		case tea.KeyUp:
			if m.address.Focused() {
				m.address.Blur()
				m.name.Focus()
			}
		case tea.KeyTab:
			if m.name.Focused() {
				m.name.Blur()
				m.address.Focus()
			} else if m.address.Focused() {
				m.address.Blur()
				m.name.Focus()
			}
		}
	}
	var nameCmd tea.Cmd
	m.name, nameCmd = m.name.Update(msg)
	var addrCmd tea.Cmd
	m.address, addrCmd = m.address.Update(msg)
	return m, tea.Batch(nameCmd, addrCmd)
}

func (m controllerPicker) View() string {
	return lipgloss.JoinVertical(
		lipgloss.Center,
		lipgloss.PlaceVertical(
			m.height-2,
			lipgloss.Center,
			lipgloss.JoinVertical(
				lipgloss.Left,
				lipgloss.NewStyle().Width(m.name.Width+lipgloss.Width(m.name.Prompt)+1).Render(m.name.View()),
				lipgloss.NewStyle().Width(m.address.Width+lipgloss.Width(m.address.Prompt)+1).Render(m.address.View()),
			)),
		m.help.ShortHelpView(m.bindings),
	)
}
