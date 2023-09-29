package models

import (
	"context"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/authmethodscmd"
)

func NewAmPicker(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int) tea.Model {
	return newItemListModel(
		ctx,
		cmd,
		previousModel,
		width,
		height,
		authmethodscmd.Lister{},
		withCustomBinding(
			key.NewBinding(key.WithKeys(tea.KeyEnter.String()), key.WithHelp(tea.KeyEnter.String(), "authenticate")),
			func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model {
				return NewPasswordLogin(ctx, cmd, previousModel, itemId, width, height)
			},
		),
	)
}
