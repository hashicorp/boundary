package messages

import (
	"context"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/internal/cmd/base"
)

type (
	DisplayModelMsg struct {
		ModelFactoryFn ModelFactoryFn
	}
	AddControllerMsg struct {
		Name    string
		Address string
	}
	SwitchControllerMsg struct {
		Index int
	}
)

type ModelFactoryFn func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model
