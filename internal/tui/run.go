package tui

import (
	tea "github.com/charmbracelet/bubbletea"

	"github.com/threatprism/threatprism/internal/config"
	"github.com/threatprism/threatprism/internal/core/engine"
)

// Run launches the interactive dashboard. It blocks until the user quits.
func Run(cfg *config.Config, eng *engine.Engine) error {
	app := NewApp(cfg, eng)
	p := tea.NewProgram(app, tea.WithAltScreen())
	// Wire the background progress channel to the program's Send so scan
	// goroutines can push updates into the update loop.
	app.SetSend(func(msg any) { p.Send(msg) })
	_, err := p.Run()
	return err
}
