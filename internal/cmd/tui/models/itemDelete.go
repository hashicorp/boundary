package models

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type ItemDeleter interface {
	Delete(context.Context, *api.Client, string) error
}

type deleteModel struct {
	*base.Command
	ctx           context.Context
	previousModel tea.Model
	itemId        string
	deleter       ItemDeleter
}

func newItemDeleteModel(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int, itemId string, deleter ItemDeleter) deleteModel {
	rm := deleteModel{
		ctx:           ctx,
		previousModel: previousModel,
		itemId:        itemId,
		Command:       cmd,
		deleter:       deleter,
	}
	return rm
}

func (m deleteModel) Init() tea.Cmd {
	return nil
}

func (m deleteModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		default:
			return m, func() tea.Msg {
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(_ context.Context, _ *base.Command, _ tea.Model, _, _ int) tea.Model {
						return m.previousModel
					},
				}
			}
		case tea.KeyEnter.String():
			return m, func() tea.Msg {
				cli, err := m.Command.Client()
				if err != nil {
					return err
				}
				if err := m.deleter.Delete(m.ctx, cli, m.itemId); err != nil {
					return err
				}
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(_ context.Context, _ *base.Command, _ tea.Model, _, _ int) tea.Model {
						return m.previousModel
					},
				}
			}
		}
	}
	return m, nil
}

func (m deleteModel) View() string {
	return "Are you sure you want to delete " + m.itemId + "?\n\nPress enter to confirm or any key to go back."
}
