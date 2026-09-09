package tui

import (
	"strconv"

	table "github.com/charmbracelet/bubbles/table"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

func hostsTableStyles() table.Styles {
	s := table.DefaultStyles()
	s.Header = s.Header.
		BorderStyle(lipgloss.NormalBorder()).
		BorderForeground(lipgloss.Color("240")).
		BorderBottom(true).
		Bold(false)
	s.Selected = s.Selected.
		Foreground(lipgloss.Color("229")).
		Background(lipgloss.Color("57")).
		Bold(false)
	return s
}

// ConnectRequest tells entrui's non-interactive path what the TUI selected.
type ConnectRequest struct {
	DaemonID int64
	Host     string
	Port     int
}

// connectModel is a compact confirmation view; pressing enter hands the
// connection over to the non-interactive `entrui connect` flow (inherited
// stdio) and quits the TUI.
type connectModel struct {
	session  *Session
	app      *app
	daemonID int64
	host     string
	port     int
	err      string
}

func newConnectModel(s *Session, a *app) connectModel {
	return connectModel{session: s, app: a}
}

func (m connectModel) start(id int64, host string) tea.Cmd {
	return func() tea.Msg {
		// default to the first allowlisted port
		port := 0
		if m.session.Hosts != nil {
			for _, h := range m.session.Hosts {
				if h.ID == id && len(h.AllowedPorts) > 0 {
					port = h.AllowedPorts[0]
					break
				}
			}
		}
		m.daemonID, m.host, m.port = id, host, port
		m.session.ConnectRequest = &ConnectRequest{DaemonID: id, Host: host, Port: port}
		_ = m.session.Close()
		return tea.Quit()
	}
}

func (m connectModel) Update(msg tea.Msg) (bool, connectModel) {
	// handoff is immediate in start(); nothing to update
	return false, m
}

func (m connectModel) View() string {
	t := defaultTheme
	port := "first allowed port"
	if m.port > 0 {
		port = strconv.Itoa(m.port)
	}
	return t.title("entrui — connecting") + "\n\n" +
		t.label("Host") + " " + m.host + "\n" +
		t.label("Port") + " " + port + "\n\n" +
		t.muted("the TUI transfers control to `entrui connect` for an interactive session…") + "\n"
}
