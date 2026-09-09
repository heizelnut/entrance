package tui

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"

	"entrance/internal/api"
)

type hostsLoadedMsg struct {
	hosts []api.DaemonView
	err   error
}

type hostsFailedMsg struct{ err error }

type hostsModel struct {
	session *Session
	app     *app
	table   table.Model
	err     string
	busy    bool
	hosts   []api.DaemonView
}

func newHostsModel(s *Session, a *app) hostsModel {
	cols := []table.Column{
		{Title: "ID", Width: 5},
		{Title: "Host", Width: 24},
		{Title: "WG IP", Width: 14},
		{Title: "Status", Width: 9},
		{Title: "Ports", Width: 18},
		{Title: "Relays", Width: 8},
	}
	t := table.New(table.WithColumns(cols), table.WithHeight(12))
	t.SetStyles(hostsTableStyles())
	return hostsModel{session: s, app: a, table: t}
}

func (m hostsModel) Init() tea.Cmd {
	return m.reload()
}

func (m hostsModel) reload() tea.Cmd {
	m.busy = true
	return func() tea.Msg {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		hosts, err := m.session.Client.ListDaemons(ctx)
		if err != nil {
			return hostsFailedMsg{err: err}
		}
		return hostsLoadedMsg{hosts: hosts}
	}
}

func (m hostsModel) Update(msg tea.Msg) (hostsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case hostsLoadedMsg:
		m.busy = false
		m.hosts = msg.hosts
		m.session.Hosts = msg.hosts
		rows := make([]table.Row, 0, len(msg.hosts))
		for _, h := range msg.hosts {
			rows = append(rows, table.Row{
				strconv.FormatInt(h.ID, 10),
				h.Hostname,
				h.WGIP,
				h.Status,
				portsStr(h.AllowedPorts),
				strconv.Itoa(h.ActiveRelays),
			})
		}
		m.table.SetRows(rows)
		return m, nil
	case hostsFailedMsg:
		m.busy = false
		m.err = msg.err.Error()
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "r", "R":
			return m, m.reload()
		case "enter":
			return m, m.connectSelected()
		case "s", "S":
			m.app.view = viewServices
			return m, m.app.svcs.Init()
		case "q":
			m.session.AppendLog("exited host list")
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	m.table, cmd = m.table.Update(msg)
	return m, cmd
}

func (m hostsModel) connectSelected() tea.Cmd {
	row := m.table.SelectedRow()
	if len(row) < 4 {
		return nil
	}
	id, err := strconv.ParseInt(row[0], 10, 64)
	if err != nil {
		m.err = "bad row"
		return nil
	}
	m.session.AppendLog("connect to host " + row[1])
	m.app.view = viewConnect
	return m.app.connect.start(id, row[1])
}

func (m hostsModel) View() string {
	t := defaultTheme
	s := t.title("entrui — hosts") + "\n"
	if m.busy {
		s += t.muted("loading…") + "\n"
	}
	if m.err != "" {
		s += t.errorText(m.err) + "\n"
	}
	s += m.table.View() + "\n"
	s += t.muted("enter: connect · r: refresh · s: services · q: quit")
	return s
}

func portsStr(ports []int) string {
	out := ""
	for i, p := range ports {
		if i > 0 {
			out += ","
		}
		out += strconv.Itoa(p)
	}
	return out
}

var _ = fmt.Sprintf
