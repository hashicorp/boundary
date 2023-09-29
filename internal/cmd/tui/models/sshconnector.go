package models

import (
	"context"
	"os/exec"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type sshConnector struct {
	ctx           context.Context
	previousModel tea.Model
	targetId      string
}

func NewSshConnector(ctx context.Context, previousModel tea.Model, targetId string) tea.Model {
	return sshConnector{
		ctx:           ctx,
		previousModel: previousModel,
		targetId:      targetId,
	}
}

func (m sshConnector) Init() tea.Cmd {
	return tea.ExecProcess(
		exec.CommandContext(m.ctx, "boundary", "connect", "ssh", "-target-id", m.targetId),
		func(err error) tea.Msg {
			if err == nil {
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
						return m.previousModel
					},
				}
			}
			return messages.DisplayModelMsg{
				ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
					// If there's an error, go back to the previous model, no this one
					return NewErrorModel(err, m.previousModel)
				},
			}
		},
	)
}

func (m sshConnector) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEscape:
			if m.previousModel != nil {
				return m, func() tea.Msg {
					return messages.DisplayModelMsg{
						ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, _, _ int) tea.Model {
							return m.previousModel
						},
					}
				}
			}
		}
		return m, tea.Quit
	}
	return m, nil
}

func (m sshConnector) View() string {
	return ""
}
