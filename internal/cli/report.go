package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/internal/report"
	"github.com/threatprism/threatprism/internal/store"
	"github.com/threatprism/threatprism/pkg/models"
)

func newReportCmd() *cobra.Command {
	var (
		formats []string
		outDir  string
		theme   string
	)
	cmd := &cobra.Command{
		Use:   "report <target>",
		Short: "Generate reports from the latest scan of a target",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := target.Parse(args[0])
			if err != nil {
				return err
			}
			res, err := latestResult(t)
			if err != nil {
				return err
			}
			if theme != "" {
				app.cfg.Report.Theme = theme
			}
			if outDir == "" {
				ws, err := app.wsm.Open(t.Host, t.URL)
				if err != nil {
					return err
				}
				outDir = ws.ReportsDir()
			}
			paths, err := generateReportsTo(res, formats, outDir)
			if err != nil {
				return err
			}
			fmt.Println(okStyle.Render(fmt.Sprintf("Generated %d report(s):", len(paths))))
			for _, p := range paths {
				fmt.Println("  " + p)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringSliceVarP(&formats, "format", "f", nil, "formats: html,pdf,markdown,json,csv (default: config)")
	f.StringVarP(&outDir, "out", "o", "", "output directory (default: workspace 18_reports)")
	f.StringVar(&theme, "theme", "", "report theme: dark, light")
	return cmd
}

// latestResult loads the most recent stored Result for a target from its
// workspace database.
func latestResult(t models.Target) (*models.Result, error) {
	ws, err := app.wsm.Open(t.Host, t.URL)
	if err != nil {
		return nil, err
	}
	st, err := store.Open(ws.DBPath())
	if err != nil {
		return nil, err
	}
	defer st.Close()

	scans, err := st.ListScans(t.URL)
	if err != nil {
		return nil, err
	}
	if len(scans) == 0 {
		return nil, fmt.Errorf("no scans found for %q — run `threatprism recon %s` first", t.Host, t.Host)
	}
	return st.Result(scans[0].ID)
}

// generateReports writes reports into the target's workspace reports dir.
func generateReports(res *models.Result, formats []string) error {
	ws, err := app.wsm.Open(res.Target.Host, res.Target.URL)
	if err != nil {
		return err
	}
	paths, err := generateReportsTo(res, formats, ws.ReportsDir())
	if err != nil {
		return err
	}
	fmt.Println(okStyle.Render(fmt.Sprintf("Reports written to %s", ws.ReportsDir())))
	for _, p := range paths {
		fmt.Println("  " + p)
	}
	return nil
}

func generateReportsTo(res *models.Result, formats []string, outDir string) ([]string, error) {
	if len(formats) == 0 {
		formats = app.cfg.Report.Formats
	}
	if len(formats) == 0 {
		formats = []string{"html", "json"}
	}
	fs := make([]report.Format, 0, len(formats))
	for _, f := range formats {
		fs = append(fs, report.Format(f))
	}
	theme := app.cfg.Report.Theme
	if theme == "" {
		theme = "dark"
	}
	return report.New().Generate(res, report.Options{
		Formats: fs,
		OutDir:  outDir,
		Theme:   theme,
	})
}
