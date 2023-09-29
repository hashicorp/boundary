package authmethodscmd

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/cursor"
	"github.com/charmbracelet/bubbles/table"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
	"github.com/hashicorp/boundary/api"
	"github.com/hashicorp/boundary/api/authmethods"
)

type Lister struct{}

func (l Lister) List(ctx context.Context, c *api.Client) tea.Msg {
	result, err := authmethods.NewClient(c).List(ctx, "global", authmethods.WithRecursive(true))
	if err != nil {
		return err
	}
	return result.GetItems()
}

func (l Lister) Populate(msg tea.Msg, t table.Model) table.Model {
	switch msg := msg.(type) {
	case []*authmethods.AuthMethod:
		var rows []table.Row
		for _, am := range msg {
			rows = append(rows, table.Row{am.Id, am.Name, am.Type, am.Scope.Id})
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
	result, err := authmethods.NewClient(c).Read(ctx, itemId)
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
	_, err := authmethods.NewClient(c).Delete(ctx, itemId)
	if err != nil {
		return err
	}
	return nil
}

type Creator struct{}

func (c Creator) TypeName() string {
	return "Auth method"
}
func (c Creator) Form() []textinput.Model {
	return []textinput.Model{
		{
			Prompt:           "Type (password, oidc or ldap): ",
			Placeholder:      "password",
			Cursor:           cursor.New(),
			PlaceholderStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
			KeyMap:           textinput.DefaultKeyMap,
		},
		{
			Prompt:           "Scope ID: ",
			Placeholder:      "global",
			Cursor:           cursor.New(),
			PlaceholderStyle: lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
			KeyMap:           textinput.DefaultKeyMap,
		},
	}
}

func (c Creator) Create(ctx context.Context, cli *api.Client, fields []textinput.Model) error {
	if len(fields) != 2 {
		return fmt.Errorf("unexpected number of fields, expected 2, got %d", len(fields))
	}
	typ := fields[0].Value()
	if typ == "" {
		typ = "password"
	}
	scopeId := fields[1].Value()
	if scopeId == "" {
		scopeId = "global"
	}
	_, err := authmethods.NewClient(cli).Create(ctx, typ, scopeId)
	if err != nil {
		return err
	}
	return nil
}
