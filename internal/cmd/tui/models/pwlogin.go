package models

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/api/authmethods"
	"github.com/hashicorp/boundary/api/authtokens"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type passwordLogin struct {
	*base.Command
	ctx           context.Context
	previousModel tea.Model
	width         int
	height        int
	amId          string
	username      textinput.Model
	password      textinput.Model
}

func NewPasswordLogin(ctx context.Context, cmd *base.Command, previousModel tea.Model, amId string, width int, height int) tea.Model {
	username := textinput.New()
	username.Prompt = "Username: "
	username.Width = int(math.Min(float64(width)*0.4, 20))
	username.Focus()
	password := textinput.New()
	password.Prompt = "Password: "
	password.Width = int(math.Min(float64(width)*0.4, 20))
	password.EchoMode = textinput.EchoPassword
	return passwordLogin{
		ctx:           ctx,
		Command:       cmd,
		previousModel: previousModel,
		width:         width,
		height:        height,
		amId:          amId,
		username:      username,
		password:      password,
	}
}

func (m passwordLogin) Init() tea.Cmd {
	return nil
}

func (m passwordLogin) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.height = msg.Height
		m.username.Width = int(math.Min(float64(msg.Width)*0.4, 20))
		m.password.Width = int(math.Min(float64(msg.Width)*0.4, 20))
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
			if m.username.Focused() {
				m.username.Blur()
				m.password.Focus()
				break
			}
			if len(m.username.Value()) == 0 || len(m.password.Value()) == 0 {
				break
			}
			return m, func() tea.Msg {
				c, err := m.Command.Client()
				if err != nil {
					return err
				}
				amc := authmethods.NewClient(c)
				result, err := amc.Authenticate(m.ctx, m.amId, "login", map[string]any{
					"login_name": m.username.Value(),
					"password":   m.password.Value(),
				})
				if err != nil {
					return err
				}
				token := new(authtokens.AuthToken)
				if err := json.Unmarshal(result.GetRawAttributes(), token); err != nil {
					return fmt.Errorf("Error trying to decode response as an auth token: %w", err)
				}
				m.Command.SaveTokenToKeyring(token)
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
						return NewWorkflowModel(ctx, cmd, width, height)
					},
				}
			}
		case tea.KeyDown:
			if m.username.Focused() {
				m.username.Blur()
				m.password.Focus()
			}
		case tea.KeyUp:
			if m.password.Focused() {
				m.password.Blur()
				m.username.Focus()
			}
		case tea.KeyTab:
			if m.username.Focused() {
				m.username.Blur()
				m.password.Focus()
			} else if m.password.Focused() {
				m.password.Blur()
				m.username.Focus()
			}
		}
	}
	var unCmd tea.Cmd
	m.username, unCmd = m.username.Update(msg)
	var pwCmd tea.Cmd
	m.password, pwCmd = m.password.Update(msg)
	return m, tea.Batch(unCmd, pwCmd)
}

func (m passwordLogin) View() string {
	return "Please login using your username and password:\n\n" + strings.Join([]string{m.username.View(), m.password.View()}, "\n")
}
