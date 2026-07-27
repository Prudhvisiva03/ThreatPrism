package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/config"
)

// Persistent flag values bound on the root command.
var (
	flagConfig    string
	flagWorkspace string
	flagLogLevel  string
	flagLogFormat string
)

// app is the shared context, populated by the root PersistentPreRunE and read
// by every subcommand's RunE.
var app *appCtx

// NewRootCmd builds the full command tree.
func NewRootCmd(version string) *cobra.Command {
	root := &cobra.Command{
		Use:   "threatprism",
		Short: "Autonomous Attack Surface Intelligence Platform",
		Long: "ThreatPrism is a modular attack-surface intelligence platform for\n" +
			"authorized reconnaissance: discovery, crawling, JS/API/login intelligence,\n" +
			"technology fingerprinting, sensitive-file and parameter discovery, security\n" +
			"analysis, screenshots, AI-assisted triage, monitoring, and reporting.\n\n" +
			"Run without a subcommand to open the interactive dashboard.",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		// Build the shared context before any subcommand runs, except for the
		// pure-config helpers that must work without a valid environment.
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if skipInit(cmd) {
				return nil
			}
			cfg, err := loadConfig()
			if err != nil {
				return err
			}
			app, err = build(cfg)
			return err
		},
		// No subcommand → interactive dashboard.
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMenu()
		},
	}

	pf := root.PersistentFlags()
	pf.StringVarP(&flagConfig, "config", "c", "", "path to config file (default: auto-discover)")
	pf.StringVar(&flagWorkspace, "workspace-dir", "", "override workspace root directory")
	pf.StringVar(&flagLogLevel, "log-level", "", "log level: debug, info, warn, error")
	pf.StringVar(&flagLogFormat, "log-format", "", "log format: text, json")

	root.AddGroup(&cobra.Group{ID: "modules", Title: "Module Commands:"})
	root.AddCommand(
		newReconCmd(),
		newMenuCmd(),
		newWorkspaceCmd(),
		newReportCmd(),
		newMonitorCmd(),
		newPluginCmd(),
		newConfigCmd(),
		newAICmd(),
		newWebCmd(),
	)
	root.AddCommand(newModuleCmds()...)

	return root
}

// loadConfig resolves configuration from the --config flag (or auto-discovery)
// and applies command-line overrides.
func loadConfig() (*config.Config, error) {
	cfg, err := config.Load(flagConfig)
	if err != nil {
		return nil, err
	}
	if flagWorkspace != "" {
		cfg.WorkspaceDir = flagWorkspace
	}
	if flagLogLevel != "" {
		cfg.Log.Level = flagLogLevel
	}
	if flagLogFormat != "" {
		cfg.Log.Format = flagLogFormat
	}
	return cfg, nil
}

// skipInit reports whether a command opts out of the shared-context bootstrap.
// Commands annotate themselves via the "skipInit" annotation.
func skipInit(cmd *cobra.Command) bool {
	for c := cmd; c != nil; c = c.Parent() {
		if c.Annotations["skipInit"] == "true" {
			return true
		}
	}
	return false
}

// Execute runs the root command and maps errors to a process exit code.
func Execute(version string) {
	if err := NewRootCmd(version).Execute(); err != nil {
		fmt.Fprintln(os.Stderr, errStyle.Render("error: ")+err.Error())
		os.Exit(1)
	}
}
