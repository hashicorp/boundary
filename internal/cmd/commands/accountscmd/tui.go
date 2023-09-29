package accountscmd

import (
	"context"
	"strings"

	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/accounts"
)

type Lister struct {
	AuthMethodId string
}

func (l Lister) List(ctx context.Context, c *api.Client) tea.Msg {
	result, err := accounts.NewClient(c).List(ctx, l.AuthMethodId)
	if err != nil {
		return err
	}
	return result.GetItems()
}

func (l Lister) Populate(msg tea.Msg, t table.Model) table.Model {
	switch msg := msg.(type) {
	case []*accounts.Account:
		var rows []table.Row
		for _, acc := range msg {
			rows = append(rows, table.Row{acc.Id, acc.Name, acc.Type, acc.Scope.Id})
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
		{Title: "Name", Width: int(float64(width) * 0.4)},
		{Title: "Type", Width: int(float64(width) * 0.2)},
		{Title: "Scope", Width: int(float64(width) * 0.2)},
	}
}

type Reader struct{}

func (r Reader) Read(ctx context.Context, c *api.Client, itemId string) tea.Msg {
	result, err := accounts.NewClient(c).Read(ctx, itemId)
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

func (r Deleter) Delete(ctx context.Context, c *api.Client, itemId string) error {
	_, err := accounts.NewClient(c).Delete(ctx, itemId)
	if err != nil {
		return err
	}
	return nil
}
