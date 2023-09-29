package models

import (
	"context"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/accountscmd"
	"github.com/hashicorp/boundary/internal/cmd/commands/authmethodscmd"
)

type child struct {
	binding key.Binding
	modelFn childFactoryFn
}

func (c child) Binding() key.Binding {
	return c.binding
}

func (c child) Model(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model {
	return c.modelFn(ctx, cmd, previousModel, width, height, itemId)
}

func newDirectory(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int) tea.Model {
	models := []modelFactory{
		{
			name: "auth methods",
			modelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int) tea.Model {
				return newItemListModel(
					ctx,
					cmd,
					previousModel,
					width,
					height,
					authmethodscmd.Lister{},
					withReader(
						authmethodscmd.Reader{},
						child{
							binding: key.NewBinding(key.WithKeys("l", "a"), key.WithHelp("l/a", "List accounts")),
							modelFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model {
								return newItemListModel(ctx, cmd, previousModel, width, height, accountscmd.Lister{AuthMethodId: itemId}, withReader(accountscmd.Reader{}, nil), withDeleter(accountscmd.Deleter{}))
							},
						},
					),
					withDeleter(authmethodscmd.Deleter{}),
					withCreator(authmethodscmd.Creator{}),
				)
			},
		},
	}
	return newModelFactoryList(ctx, cmd, previousModel, width, height, "Please select a resource to inspect:", models)
}
