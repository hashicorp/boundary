package tui

import (
	"context"
	"io"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
	models "github.com/hashicorp/boundary/internal/cmd/tui/models"
	"github.com/mitchellh/cli"
)

func ServeTui(ctx context.Context) error {
	p := tea.NewProgram(newRootModel(ctx), tea.WithContext(ctx), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		return err
	}
	return nil
}

type controller struct {
	name    string
	address string
	cmd     *base.Command
}

type root struct {
	ctx             context.Context
	child           tea.Model
	style           lipgloss.Style
	controllers     []controller
	controllerIndex int
}

type noOpModel struct{}

func (noOpModel) Init() tea.Cmd                         { return nil }
func (n noOpModel) Update(tea.Msg) (tea.Model, tea.Cmd) { return n, nil }
func (noOpModel) View() string {
	return ""
}

func newRootModel(ctx context.Context) tea.Model {
	cfg, err := api.DefaultConfig()
	if err != nil {
		return models.NewErrorModel(err, nil)
	}
	return root{
		ctx:   ctx,
		style: lipgloss.NewStyle().Margin(1).Padding(1).Border(lipgloss.NormalBorder()),
		child: noOpModel{},
		controllers: []controller{
			{
				name:    base.DefaultTokenName,
				address: cfg.Addr,
				cmd: base.NewCommand(&cli.BasicUi{
					Writer:      io.Discard,
					ErrorWriter: io.Discard,
				}),
			},
		},
	}
}

func (m root) Init() tea.Cmd {
	return func() tea.Msg {
		cmd := m.controllers[m.controllerIndex].cmd
		cmd.FlagKeyringType = "auto"
		cmd.FlagTokenName = m.controllers[m.controllerIndex].name
		keyRingType, tokenName, err := cmd.DiscoverKeyringTokenInfo()
		if err != nil {
			return messages.DisplayModelMsg{
				ModelFactoryFn: models.NewAmPicker,
			}
		}
		token := cmd.ReadTokenFromKeyring(keyRingType, tokenName)
		if token == nil {
			return messages.DisplayModelMsg{
				ModelFactoryFn: models.NewAmPicker,
			}
		}
		cli, err := cmd.Client()
		if err != nil {
			return messages.DisplayModelMsg{
				ModelFactoryFn: models.NewAmPicker,
			}
		}
		_, err = authtokens.NewClient(cli).Read(m.ctx, token.Id)
		if err != nil {
			return messages.DisplayModelMsg{
				ModelFactoryFn: models.NewAmPicker,
			}
		}
		return messages.DisplayModelMsg{
			ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
				return models.NewWorkflowModel(ctx, cmd, width, height)
			},
		}
	}
}

func (m root) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case error:
		m.child = models.NewErrorModel(msg, m.child)
		// TODO: Using ClearScreen is a hack
		return m, tea.Sequence(tea.ClearScreen, m.child.Init())
	case messages.DisplayModelMsg:
		c := m.child
		if _, ok := c.(noOpModel); ok {
			// Don't pass in the noopmodel to the factory function
			c = nil
		}
		m.child = msg.ModelFactoryFn(m.ctx, m.controllers[m.controllerIndex].cmd, c, m.style.GetWidth(), m.style.GetHeight())
		return m, tea.Sequence(tea.ClearScreen, m.child.Init())
	case messages.AddControllerMsg:
		m.controllers = append(m.controllers, controller{
			name:    msg.Name,
			address: msg.Address,
			cmd: base.NewCommand(&cli.BasicUi{
				Writer:      io.Discard,
				ErrorWriter: io.Discard,
			}),
		})
		m.controllerIndex++
		return m, m.Init()
	case messages.SwitchControllerMsg:
		m.controllerIndex = msg.Index
		return m, m.Init()
	case tea.WindowSizeMsg:
		// Compensate for margin, padding and border
		msg.Width -= m.style.GetHorizontalFrameSize()
		msg.Height -= m.style.GetVerticalFrameSize()
		m.style.Width(msg.Width)
		m.style.Height(msg.Height)
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyCtrlC:
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.child, cmd = m.child.Update(msg)
	return m, cmd
}

func (m root) View() string {
	s := "Loading..."
	if m.child != nil {
		s = m.child.View()
	}
	return m.style.Render(lipgloss.Place(m.style.GetWidth(), m.style.GetHeight(), lipgloss.Center, lipgloss.Center, s))
}
