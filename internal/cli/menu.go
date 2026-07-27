package cli

import (
	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/tui"
)

func runMenu() error {
	return tui.Run(app.cfg, app.engine)
}

func newMenuCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "menu",
		Short: "Open the interactive terminal dashboard",
		RunE: func(cmd *cobra.Command, args []string) error {
			return runMenu()
		},
	}
}
