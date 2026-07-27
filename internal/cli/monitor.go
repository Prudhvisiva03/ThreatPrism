package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/core/engine"
	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/pkg/models"
)

func newMonitorCmd() *cobra.Command {
	var quiet bool
	cmd := &cobra.Command{
		Use:   "monitor <target>",
		Short: "Re-scan a target and diff against the previous scan",
		Long: "Runs the monitoring module, which compares the current attack surface\n" +
			"against the most recent stored scan and reports new or changed assets.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := target.Parse(args[0])
			if err != nil {
				return err
			}
			fmt.Println(headerStyle.Render("ThreatPrism monitor") + mutedStyle.Render("  "+t.Host))
			res, err := app.engine.Run(context.Background(), t, engine.Options{
				Mode:     models.Mode(app.cfg.Recon.DefaultMode),
				Progress: cliProgress{quiet: quiet},
			})
			if err != nil {
				return err
			}
			printResult(res)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&quiet, "quiet", "q", false, "suppress per-module progress output")
	return cmd
}
