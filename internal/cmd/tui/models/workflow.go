package models

import (
	"context"

	"github.com/charmbracelet/bubbles/key"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/commands/targetscmd"
)

func NewWorkflowModel(ctx context.Context, cmd *base.Command, width int, height int) tea.Model {
	models := []modelFactory{
		{
			name: "I want to connect to a target",
			modelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
				return newItemListModel(
					ctx,
					cmd,
					previousModel,
					width,
					height,
					targetscmd.Lister{},
					withCustomBinding(
						key.NewBinding(key.WithKeys(tea.KeyEnter.String()), key.WithHelp(tea.KeyEnter.String(), "connect")),
						func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model {
							return NewSshConnector(ctx, previousModel, itemId)
						},
					),
				)
			},
		},
		{
			name: "I want to connect to a different Boundary controller",
			modelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
				return NewControllerPicker(ctx, cmd, previousModel, width, height)
			},
		},
		{
			name: "I want to perform administrative tasks such as creating or inspecting resources",
			modelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
				return newDirectory(ctx, cmd, previousModel, width, height)
			},
		},
	}
	return newModelFactoryList(ctx, cmd, nil, width, height, "Welcome to Boundary! What do you want to do?", models)
}
