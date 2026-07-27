package tui

import (
	"fmt"

	"github.com/threatprism/threatprism/pkg/models"
)

// tea message types emitted during a scan. They flow from the background scan
// goroutine into the BubbleTea update loop via (*tea.Program).Send.

type moduleStageMsg struct{ slug, name string }
type moduleStepMsg struct{ text string }
type moduleDoneMsg struct {
	slug     string
	findings int
}
type scanFinishedMsg struct {
	result *models.Result
	err    error
}

// teaProgress implements module.Progress by forwarding updates to the TUI
// program. The send func is (*tea.Program).Send.
type teaProgress struct {
	send func(any)
}

func (p teaProgress) Stage(slug, name string) { p.send(moduleStageMsg{slug, name}) }

func (p teaProgress) Stepf(format string, args ...any) {
	p.send(moduleStepMsg{fmt.Sprintf(format, args...)})
}

func (p teaProgress) Done(slug string, findings int) { p.send(moduleDoneMsg{slug, findings}) }
