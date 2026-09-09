package tui

import "strings"

// streamview renders the session transcript (used by the non-interactive
// connect flow to show tunnel status lines alongside the live ssh session).
type streamview struct {
	session *Session
}

func newStreamView(s *Session) *streamview { return &streamview{session: s} }

// Render returns the last N log lines joined for display/printing.
func (v *streamview) Render(n int) string {
	log := v.session.Log
	if n > 0 && len(log) > n {
		log = log[len(log)-n:]
	}
	return strings.Join(log, "\n")
}
