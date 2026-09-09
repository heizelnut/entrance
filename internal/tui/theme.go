package tui

import "github.com/charmbracelet/lipgloss"

// Theme is the entrui lipgloss palette.
type theme struct {
	primary    lipgloss.Color
	secondary  lipgloss.Color
	errColor   lipgloss.Color
	mutedColor lipgloss.Color
}

var defaultTheme = theme{
	primary:    lipgloss.Color("39"),  // blue
	secondary:  lipgloss.Color("214"), // orange
	errColor:   lipgloss.Color("196"), // red
	mutedColor: lipgloss.Color("240"),
}

func (t theme) title(s string) string {
	return lipgloss.NewStyle().Foreground(t.primary).Bold(true).Padding(0, 1).Render(s)
}

func (t theme) label(s string) string {
	return lipgloss.NewStyle().Foreground(t.secondary).Bold(true).Render(s)
}

func (t theme) errorText(s string) string {
	return lipgloss.NewStyle().Foreground(t.errColor).Render(s)
}

func (t theme) muted(s string) string {
	return lipgloss.NewStyle().Foreground(t.mutedColor).Render(s)
}
