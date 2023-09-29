package models

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
	"github.com/muesli/reflow/wordwrap"
)

type errorModel struct {
	err           error
	previousModel tea.Model
}

func NewErrorModel(err error, previousModel tea.Model) errorModel {
	return errorModel{
		err:           err,
		previousModel: previousModel,
	}
}

func (m errorModel) Init() tea.Cmd {
	return nil
}

func (m errorModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
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

func (m errorModel) View() string {
	s := "There was an error:\n\n" + wordwrap.String(m.err.Error(), 80) + "\n\n"
	if m.previousModel == nil {
		s += "Press any key to quit."
	} else {
		s += "Press esc to go back or any other key to quit."
	}
	return s
}
