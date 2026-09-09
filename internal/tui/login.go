package tui

import (
	"context"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"

	"entrance/internal/client"
)

type loginModel struct {
	session *Session
	app     *app
	url     textinput.Model
	user    textinput.Model
	pass    textinput.Model
	err     string
	busy    bool
	focused int
}

func newLoginModel(s *Session, a *app) loginModel {
	dims := func(v string) textinput.Model {
		t := textinput.New()
		t.Placeholder = v
		t.Width = 40
		return t
	}
	m := loginModel{
		session: s,
		app:     a,
		url:     dims("https://bastion.example.com:8443"),
		user:    dims("admin"),
		pass:    dims("password"),
		focused: 0,
	}
	m.url.SetValue(s.URL)
	m.user.SetValue(s.Username)
	m.user.Focus()
	return m
}

func (m loginModel) Init() tea.Cmd { return nil }

func (m loginModel) Update(msg tea.Msg) (loginModel, tea.Cmd) {
	if done, ok := msg.(loginDoneMsg); ok {
		m.busy = false
		if done.err != nil {
			m.err = done.err.Error()
			return m, nil
		}
		m.app.view = viewHosts
		return m, m.app.hosts.Init()
	}
	if m.busy {
		return m, nil
	}
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab", "down":
			m.focused = (m.focused + 1) % 3
			m.setFocus()
		case "up":
			m.focused = (m.focused + 2) % 3
			m.setFocus()
		case "enter":
			if m.focused == 2 {
				return m, m.submit()
			}
			m.focused = (m.focused + 1) % 3
			m.setFocus()
		case "ctrl+c":
			return m, tea.Quit
		}
	}
	var cmd tea.Cmd
	if m.focused == 0 {
		m.url, cmd = m.url.Update(msg)
	} else if m.focused == 1 {
		m.user, cmd = m.user.Update(msg)
	} else {
		m.pass, cmd = m.pass.Update(msg)
	}
	return m, cmd
}

func (m *loginModel) setFocus() {
	m.url.Blur()
	m.user.Blur()
	m.pass.Blur()
	switch m.focused {
	case 0:
		m.url.Focus()
	case 1:
		m.user.Focus()
	case 2:
		m.pass.Focus()
	}
}

type loginDoneMsg struct {
	ok  bool
	err error
}

func (m loginModel) submit() tea.Cmd {
	url := strings.TrimSpace(m.url.Value())
	if url == "" {
		m.err = "enter the control plane URL"
		return nil
	}
	if !strings.HasPrefix(url, "https://") {
		url = "https://" + url
		m.url.SetValue(url)
	}
	m.busy = true
	username := m.user.Value()
	password := m.pass.Value()
	return func() tea.Msg {
		c, err := client.New(client.Options{BaseURL: url, CAFile: m.session.CAFile})
		if err != nil {
			return loginDoneMsg{err: err}
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		resp, err := c.Login(ctx, username, password)
		if err != nil {
			return loginDoneMsg{err: err}
		}
		m.session.URL = url
		m.session.Username = username
		m.session.Token = resp.SessionToken
		m.session.TokenExp = resp.ExpiresAt.Unix()
		m.session.Client = c
		m.session.save()
		m.session.AppendLog("logged in as " + username)
		return loginDoneMsg{ok: true}
	}
}

func (m loginModel) View() string {
	t := defaultTheme
	s := t.title("entrui — bastion login") + "\n\n"
	s += t.label("Server URL") + "\n" + m.url.View() + "\n\n"
	s += t.label("Username") + "\n" + m.user.View() + "\n\n"
	s += t.label("Password") + "\n" + m.pass.View() + "\n\n"
	if m.err != "" {
		s += t.errorText(m.err) + "\n"
	}
	if m.busy {
		s += t.muted("signing in…")
	} else {
		s += t.muted("tab: move · enter: continue · ctrl+c: quit") + "\n"
	}
	return s
}
