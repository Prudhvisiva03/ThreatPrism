package tui

import (
	"context"
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/spinner"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/threatprism/threatprism/internal/config"
	"github.com/threatprism/threatprism/internal/core/engine"
	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/pkg/models"
)

type screen int

const (
	screenMenu screen = iota
	screenTarget
	screenMode
	screenRunning
	screenResults
)

// menuEntry is one main-menu row.
type menuEntry struct {
	num  string
	name string
	desc string
	mode models.Mode // non-empty when the entry maps directly to a custom single-module run
	slug string       // module slug for single-module entries
}

var mainMenu = []menuEntry{
	{"1", "Passive OSINT Recon", "Zero-contact passive intelligence (CT Logs, Passive DNS, Wayback archives)", models.ModeQuick, ""},
	{"2", "Standard Recon", "Balanced passive + live host probing + header analysis", models.ModeStandard, ""},
	{"3", "Deep Attack Surface Discovery", "Exhaustive crawling, JS secrets, APIs, & sensitive files", models.ModeDeep, ""},
	{"4", "JavaScript Intelligence", "Analyze JS bundles for endpoints, API keys, & secrets", models.ModeCustom, "jsintel"},
	{"5", "API Intelligence", "Discover REST, GraphQL, Swagger, & OpenAPI surfaces", models.ModeCustom, "apiintel"},
	{"6", "Login & Auth Intelligence", "Identify login portals, admin panels, & auth mechanisms", models.ModeCustom, "loginintel"},
	{"7", "Technology Fingerprinting", "Detect servers, frameworks, CDNs, & WAFs", models.ModeCustom, "techfp"},
	{"8", "Sensitive Files & Configs", "Probe for exposed .env, .git, backups, & credentials", models.ModeCustom, "sensitive"},
	{"9", "Security Analysis", "Inspect security headers, CORS, cookies, & TLS posture", models.ModeCustom, "security"},
	{"10", "Web Workspace Dashboard", "Launch interactive browser dashboard server", "", ""},
	{"11", "Workspace Manager", "Browse per-target databases & scan history", "", ""},
	{"12", "AI Triage Assistant", "Explain findings and prioritize risk posture", "", ""},
	{"0", "Exit", "Quit ThreatPrism", "", ""},
}

// App is the root BubbleTea model.
type App struct {
	cfg    *config.Config
	eng    *engine.Engine
	send   func(any)

	screen   screen
	cursor   int
	target   models.Target
	input    textinput.Model
	spin     spinner.Model
	modeCur  int
	modes    []models.Mode

	// running state
	current  string
	logLines []string
	result   *models.Result
	err      error
	width    int
	height   int

	selectedEntry menuEntry
}

// NewApp builds the root model.
func NewApp(cfg *config.Config, eng *engine.Engine) *App {
	ti := textinput.New()
	ti.Placeholder = "https://target.com"
	ti.CharLimit = 200
	ti.Width = 50

	sp := spinner.New()
	sp.Spinner = spinner.Dot
	sp.Style = lipgloss.NewStyle().Foreground(colAccent)

	return &App{
		cfg:   cfg,
		eng:   eng,
		input: ti,
		spin:  sp,
		modes: models.AllModes(),
	}
}

// Init implements tea.Model.
func (a *App) Init() tea.Cmd { return a.spin.Tick }

// SetSend wires the program's Send function for background progress delivery.
func (a *App) SetSend(send func(any)) { a.send = send }

// Update implements tea.Model.
func (a *App) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		a.width, a.height = msg.Width, msg.Height
		return a, nil

	case spinner.TickMsg:
		var cmd tea.Cmd
		a.spin, cmd = a.spin.Update(msg)
		return a, cmd

	case moduleStageMsg:
		a.current = msg.name
		a.logLines = append(a.logLines, accentStyle.Render("▶ "+msg.name))
		return a, nil
	case moduleStepMsg:
		a.logLines = append(a.logLines, "  "+labelStyle.Render(msg.text))
		a.trimLog()
		return a, nil
	case moduleDoneMsg:
		a.logLines = append(a.logLines, okStyle.Render(fmt.Sprintf("  ✓ %s (%d findings)", msg.slug, msg.findings)))
		a.trimLog()
		return a, nil
	case scanFinishedMsg:
		a.result = msg.result
		a.err = msg.err
		a.screen = screenResults
		return a, nil

	case tea.KeyMsg:
		return a.handleKey(msg)
	}
	return a, nil
}

func (a *App) handleKey(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch a.screen {
	case screenMenu:
		return a.keyMenu(msg)
	case screenTarget:
		return a.keyTarget(msg)
	case screenMode:
		return a.keyMode(msg)
	case screenResults:
		if msg.String() == "q" || msg.Type == tea.KeyEsc {
			a.screen = screenMenu
			a.result = nil
			return a, nil
		}
	case screenRunning:
		if msg.Type == tea.KeyCtrlC {
			return a, tea.Quit
		}
	}
	if msg.Type == tea.KeyCtrlC {
		return a, tea.Quit
	}
	return a, nil
}

func (a *App) keyMenu(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.cursor > 0 {
			a.cursor--
		}
	case "down", "j":
		if a.cursor < len(mainMenu)-1 {
			a.cursor++
		}
	case "q":
		return a, tea.Quit
	case "enter":
		return a.selectMenu(mainMenu[a.cursor])
	default:
		// Number shortcuts.
		for i, e := range mainMenu {
			if e.num == msg.String() {
				a.cursor = i
				return a.selectMenu(e)
			}
		}
	}
	return a, nil
}

func (a *App) selectMenu(e menuEntry) (tea.Model, tea.Cmd) {
	if e.name == "Exit" {
		return a, tea.Quit
	}
	a.selectedEntry = e
	// Entries that need a target go through target input.
	a.input.SetValue("")
	a.input.Focus()
	a.screen = screenTarget
	return a, textinput.Blink
}

func (a *App) keyTarget(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		a.screen = screenMenu
		return a, nil
	case tea.KeyEnter:
		t, err := target.Parse(a.input.Value())
		if err != nil {
			a.err = err
			return a, nil
		}
		a.target = t
		a.err = nil
		if a.selectedEntry.mode != "" {
			if a.selectedEntry.mode == models.ModeCustom {
				return a.startScan(models.ModeCustom, []string{a.selectedEntry.slug})
			}
			return a.startScan(a.selectedEntry.mode, nil)
		}
		return a.startScan(models.ModeStandard, nil)
	}
	var cmd tea.Cmd
	a.input, cmd = a.input.Update(msg)
	return a, cmd
}

func (a *App) keyMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "up", "k":
		if a.modeCur > 0 {
			a.modeCur--
		}
	case "down", "j":
		if a.modeCur < len(a.modes)-1 {
			a.modeCur++
		}
	case "esc":
		a.screen = screenMenu
	case "enter":
		mode := a.modes[a.modeCur]
		if mode == models.ModeCustom {
			return a.startScan(mode, a.cfg.Recon.CustomModules)
		}
		return a.startScan(mode, nil)
	}
	return a, nil
}

// startScan launches the engine in a goroutine and switches to the running view.
func (a *App) startScan(mode models.Mode, custom []string) (tea.Model, tea.Cmd) {
	a.screen = screenRunning
	a.logLines = nil
	a.current = "starting…"
	a.result = nil
	a.err = nil

	prog := teaProgress{send: a.send}
	go func() {
		res, err := a.eng.Run(context.Background(), a.target, engine.Options{
			Mode: mode, CustomModules: custom, Progress: prog,
		})
		a.send(scanFinishedMsg{result: res, err: err})
	}()
	return a, a.spin.Tick
}

func (a *App) trimLog() {
	const max = 200
	if len(a.logLines) > max {
		a.logLines = a.logLines[len(a.logLines)-max:]
	}
}

// View implements tea.Model.
func (a *App) View() string {
	switch a.screen {
	case screenMenu:
		return a.viewMenu()
	case screenTarget:
		return a.viewTarget()
	case screenMode:
		return a.viewMode()
	case screenRunning:
		return a.viewRunning()
	case screenResults:
		return a.viewResults()
	}
	return ""
}

func header() string {
	return titleStyle.Render("ThreatPrism") + "  " +
		subtitleStyle.Render("Autonomous Attack Surface Intelligence Platform")
}

func (a *App) viewMenu() string {
	var b strings.Builder
	b.WriteString(header() + "\n\n")
	for i, e := range mainMenu {
		num := menuNumStyle.Render(pad(e.num, 2))
		line := fmt.Sprintf("%s  %s", num, e.name)
		if i == a.cursor {
			line = menuSelStyle.Render(fmt.Sprintf("%s  %s", menuSelNumStyle.Render(pad(e.num, 2)), e.name))
			line += "  " + menuDescStyle.Render(e.desc)
		} else {
			line = menuItemStyle.Render(line)
		}
		b.WriteString(line + "\n")
	}
	b.WriteString(helpStyle.Render("\n↑/↓ navigate · number to jump · enter select · q quit"))
	return panelStyle.Render(b.String())
}

func (a *App) viewTarget() string {
	var b strings.Builder
	b.WriteString(header() + "\n\n")
	b.WriteString(accentStyle.Render(a.selectedEntry.name) + "\n")
	b.WriteString(labelStyle.Render("Enter target URL or domain:") + "\n\n")
	b.WriteString(a.input.View() + "\n")
	if a.err != nil {
		b.WriteString("\n" + errStyle.Render(a.err.Error()) + "\n")
	}
	b.WriteString(helpStyle.Render("\nenter confirm · esc back"))
	return panelStyle.Render(b.String())
}

func (a *App) viewMode() string {
	var b strings.Builder
	b.WriteString(header() + "\n\n")
	b.WriteString(accentStyle.Render("Select Recon Mode for "+a.target.Host) + "\n\n")
	for i, m := range a.modes {
		cursor := "  "
		name := menuItemStyle.Render(strings.Title(string(m)))
		if i == a.modeCur {
			cursor = accentStyle.Render("▸ ")
			name = menuSelStyle.Render(strings.Title(string(m)))
		}
		b.WriteString(fmt.Sprintf("%s%s  %s\n", cursor, name, menuDescStyle.Render(m.Describe())))
	}
	b.WriteString(helpStyle.Render("\n↑/↓ navigate · enter start · esc back"))
	return panelStyle.Render(b.String())
}

func (a *App) viewRunning() string {
	var b strings.Builder
	b.WriteString(header() + "\n\n")
	b.WriteString(a.spin.View() + " " + accentStyle.Render("Scanning "+a.target.Host) + "  " +
		labelStyle.Render("· "+a.current) + "\n\n")
	start := 0
	if len(a.logLines) > 18 {
		start = len(a.logLines) - 18
	}
	for _, l := range a.logLines[start:] {
		b.WriteString(l + "\n")
	}
	b.WriteString(helpStyle.Render("\nctrl+c cancel"))
	return panelStyle.Render(b.String())
}

func (a *App) viewResults() string {
	var b strings.Builder
	b.WriteString(header() + "\n\n")
	if a.err != nil {
		b.WriteString(errStyle.Render("Scan failed: "+a.err.Error()) + "\n")
		b.WriteString(helpStyle.Render("\nq back to menu"))
		return panelStyle.Render(b.String())
	}
	r := a.result
	b.WriteString(accentStyle.Render("Results for "+r.Target.Host) + "\n\n")
	b.WriteString(riskLine(r) + "\n\n")

	stats := [][2]string{
		{"Subdomains", itoa(len(r.Subdomains))},
		{"Alive Hosts", itoa(len(r.Hosts))},
		{"JS Files", itoa(len(r.JSFiles))},
		{"APIs", itoa(len(r.APIEndpoints))},
		{"Login Pages", itoa(len(r.LoginPages))},
		{"Sensitive Files", itoa(len(r.SensitiveFiles))},
		{"Secrets", itoa(len(r.Secrets))},
		{"Parameters", itoa(len(r.Parameters))},
		{"Findings", itoa(len(r.Findings))},
	}
	for _, s := range stats {
		b.WriteString(labelStyle.Render(pad(s[0], 18)) + " " + valueStyle.Render(s[1]) + "\n")
	}

	// Top findings by severity.
	b.WriteString("\n" + accentStyle.Render("Top Findings") + "\n")
	shown := 0
	for _, f := range topFindings(r.Findings) {
		if shown >= 8 {
			break
		}
		sv := severityStyle(strings.ToLower(string(f.Severity))).Render(strings.ToUpper(string(f.Severity)))
		b.WriteString(fmt.Sprintf("  %s  %s\n", sv, f.Title))
		shown++
	}

	b.WriteString(helpStyle.Render("\nq back to menu · reports saved in the workspace"))
	return panelStyle.Render(b.String())
}
