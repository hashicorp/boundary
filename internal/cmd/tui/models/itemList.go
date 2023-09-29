package models

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/help"
	"github.com/charmbracelet/bubbles/key"
	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/internal/cmd/base"
	"github.com/hashicorp/boundary/internal/cmd/tui/messages"
)

type option func(*listModel)

type childFactoryFn func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model

func withReader(itemReader ItemReader, child ChildModel) option {
	return func(lm *listModel) {
		mfn := func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model {
			return newItemReadModel(ctx, cmd, previousModel, width, height, itemId, itemReader, child)
		}
		lm.customBindings[tea.KeyEnter.String()] = mfn
	}
}

func withDeleter(itemDeleter ItemDeleter) option {
	return func(lm *listModel) {
		lm.bindings = append(lm.bindings, key.NewBinding(key.WithKeys("d", tea.KeyDelete.String()), key.WithHelp("d", "Delete")))
		mfn := func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model {
			return newItemDeleteModel(ctx, cmd, previousModel, width, height, itemId, itemDeleter)
		}
		lm.customBindings["d"] = mfn
		lm.customBindings[tea.KeyDelete.String()] = mfn
	}
}

func withCreator(itemCreator ItemCreator) option {
	return func(lm *listModel) {
		lm.bindings = append(lm.bindings, key.NewBinding(key.WithKeys("c"), key.WithHelp("c", "Create new")))
		lm.customBindings["c"] = func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, _ string) tea.Model {
			return newItemCreateModel(ctx, cmd, previousModel, width, height, itemCreator)
		}
	}
}

func withCustomBinding(binding key.Binding, modelFactory func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int, itemId string) tea.Model) option {
	return func(lm *listModel) {
		lm.bindings = append(lm.bindings, binding)
		for _, key := range binding.Keys() {
			lm.customBindings[key] = modelFactory
		}
	}
}

type ItemLister interface {
	List(context.Context, *api.Client) tea.Msg
	Populate(tea.Msg, table.Model) table.Model
	Columns(int) []table.Column
}

type listModel struct {
	*base.Command
	ctx            context.Context
	previousModel  tea.Model
	ams            table.Model
	help           help.Model
	bindings       []key.Binding
	lister         ItemLister
	customBindings map[string]childFactoryFn
}

func newItemListModel(ctx context.Context, cmd *base.Command, previousModel tea.Model, width int, height int, lister ItemLister, opts ...option) tea.Model {
	s := table.Styles{
		Header:   lipgloss.NewStyle().Bold(true).PaddingBottom(1),
		Cell:     lipgloss.NewStyle(),
		Selected: lipgloss.NewStyle().Bold(true).Background(lipgloss.Color("#000000")).Foreground(lipgloss.Color("#ffffff")),
	}
	t := table.New(
		table.WithWidth(width-3), // Yep, 3
		table.WithHeight(height-2),
		table.WithStyles(s),
	)
	// Overlaps with the binding used to delete
	t.KeyMap.PageDown.SetEnabled(false)
	hp := help.New()
	hp.Width = width
	lm := listModel{
		ctx:           ctx,
		Command:       cmd,
		previousModel: previousModel,
		ams:           t,
		help:          hp,
		bindings: []key.Binding{
			t.KeyMap.LineUp,
			t.KeyMap.LineDown,
			key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back")),
		},
		lister:         lister,
		customBindings: make(map[string]childFactoryFn),
	}
	for _, opt := range opts {
		opt(&lm)
	}
	return lm
}

func (m listModel) Init() tea.Cmd {
	return func() tea.Msg {
		c, err := m.Command.Client()
		if err != nil {
			return err
		}
		msg := m.lister.List(m.ctx, c)
		if err, ok := msg.(error); ok && err != nil {
			if strings.Contains(err.Error(), "connect: connection refused") {
				err = fmt.Errorf("Couldn't find a Boundary controller running on %q. Set $BOUNDARY_ADDRESS to override the default address. The error was:\n\n%w", c.Addr(), err)
			}
			return messages.DisplayModelMsg{
				ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
					// If there's an error, go back to the previous model, no this one
					return NewErrorModel(err, m.previousModel)
				},
			}
		}
		return msg
	}
}

func (m listModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.ams.SetWidth(msg.Width - 10) // ??
		m.ams.SetHeight(msg.Height - 8)
		m.ams.SetColumns(m.lister.Columns(m.ams.Width()))
		m.help.Width = msg.Width
	case tea.KeyMsg:
		// Let custom bindings take precedent
		if mfn, ok := m.customBindings[msg.String()]; ok {
			return m, func() tea.Msg {
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(ctx context.Context, cmd *base.Command, previousModel tea.Model, width, height int) tea.Model {
						return mfn(ctx, cmd, previousModel, width, height, m.ams.SelectedRow()[0])
					},
				}
			}
		}
		switch msg.Type {
		case tea.KeyEscape:
			return m, func() tea.Msg {
				return messages.DisplayModelMsg{
					ModelFactoryFn: func(_ context.Context, _ *base.Command, _ tea.Model, _, _ int) tea.Model {
						return m.previousModel
					},
				}
			}
		}
	}
	m.ams = m.lister.Populate(msg, m.ams)
	var cmd tea.Cmd
	m.ams, cmd = m.ams.Update(msg)
	return m, cmd
}

func (m listModel) View() string {
	return lipgloss.JoinVertical(lipgloss.Center, m.ams.View(), m.help.ShortHelpView(m.bindings))
}
