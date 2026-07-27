package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/core/engine"
	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/pkg/models"
)

func newReconCmd() *cobra.Command {
	var (
		mode    string
		mods    []string
		quiet   bool
		noRepo  bool
		formats []string
	)

	cmd := &cobra.Command{
		Use:   "recon <target>",
		Short: "Run a full reconnaissance scan against a target",
		Long: "Runs a reconnaissance scan against a target URL or domain.\n\n" +
			"Modes:\n" +
			"  quick     fast passive surface sweep\n" +
			"  standard  balanced passive + light active (default)\n" +
			"  deep      exhaustive active reconnaissance\n" +
			"  custom    only the modules named with --modules",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := target.Parse(args[0])
			if err != nil {
				return err
			}

			m := models.Mode(mode)
			if len(mods) > 0 && !cmd.Flags().Changed("mode") {
				m = models.ModeCustom
			}
			if !m.Valid() {
				return fmt.Errorf("invalid mode %q (want quick|standard|deep|custom)", mode)
			}

			fmt.Println(headerStyle.Render("ThreatPrism recon") + mutedStyle.Render(
				fmt.Sprintf("  %s · %s mode", t.Host, m)))

			res, err := app.engine.Run(context.Background(), t, engine.Options{
				Mode:          m,
				CustomModules: mods,
				Progress:      cliProgress{quiet: quiet},
			})
			if err != nil {
				return err
			}

			printResult(res)

			if len(formats) > 0 {
				if err := generateReports(res, formats); err != nil {
					return err
				}
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.StringVarP(&mode, "mode", "m", "standard", "scan mode: quick, standard, deep, custom")
	f.StringSliceVar(&mods, "modules", nil, "modules to run (implies custom mode)")
	f.BoolVarP(&quiet, "quiet", "q", false, "suppress per-module progress output")
	f.BoolVar(&noRepo, "no-report", false, "skip report generation")
	f.StringSliceVar(&formats, "report", nil, "also generate reports: html,pdf,markdown,json,csv")
	return cmd
}
