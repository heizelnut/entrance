package tui

import (
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

// servicesModel is a minimal services list view (services land in phase 2;
// kept as a real but simple screen so `s` in the host list has a target).
type servicesModel struct {
	session *Session
	app     *app
	lines   []string
}

func newServicesModel(s *Session, a *app) servicesModel {
	return servicesModel{session: s, app: a, lines: []string{
		"Services management arrives in phase 2.",
		"",
		"Today: open a connection from the host list (enter)",
	}}
}

func (m servicesModel) Init() tea.Cmd { return nil }

func (m servicesModel) Update(msg tea.Msg) (servicesModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc":
			m.app.view = viewHosts
			return m, m.app.hosts.Init()
		case "h":
			m.app.view = viewHosts
			return m, m.app.hosts.Init()
		}
	}
	return m, nil
}

func (m servicesModel) View() string {
	t := defaultTheme
	return t.title("entrui — services") + "\n\n" +
		strings.Join(m.lines, "\n") + "\n\n" +
		t.muted("h: back to hosts · q: quit")
}
