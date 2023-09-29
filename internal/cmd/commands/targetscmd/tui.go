package targetscmd

import (
	"context"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/targets"
)

type Lister struct{}

func (l Lister) List(ctx context.Context, c *api.Client) tea.Msg {
	result, err := targets.NewClient(c).List(ctx, "global", targets.WithRecursive(true))
	if err != nil {
		return err
	}
	return result.GetItems()
}

func (l Lister) Populate(msg tea.Msg, t table.Model) table.Model {
	switch msg := msg.(type) {
	case []*targets.Target:
		var rows []table.Row
		for _, target := range msg {
			rows = append(rows, table.Row{target.Id, target.Name, target.Address, target.Type, target.Scope.Id})
		}
		t.SetColumns(l.Columns(t.Width()))
		t.SetRows(rows)
		t.Focus()
	}
	return t
}

func (l Lister) Columns(width int) []table.Column {
	return []table.Column{
		{Title: "ID", Width: int(float64(width) * 0.2)},
		{Title: "Name", Width: int(float64(width) * 0.3)},
		{Title: "Address", Width: int(float64(width) * 0.2)},
		{Title: "Type", Width: int(float64(width) * 0.1)},
		{Title: "Scope", Width: int(float64(width) * 0.2)},
	}
}

type Reader struct{}

func (r Reader) Read(ctx context.Context, c *api.Client, itemId string) tea.Msg {
	result, err := targets.NewClient(c).Read(ctx, itemId)
	if err != nil {
		return err
	}
	return printItemTable(result.GetItem(), nil)
}

func (r Reader) Populate(msg tea.Msg, v viewport.Model) (viewport.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case string:
		v.SetContent(strings.TrimSpace(msg))
	}
	return v, nil
}

type Deleter struct{}

func (d Deleter) Delete(ctx context.Context, c *api.Client, itemId string) error {
	_, err := targets.NewClient(c).Delete(ctx, itemId)
	if err != nil {
		return err
	}
	return nil
}
