package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/store"
)

func newWorkspaceCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:     "workspace",
		Aliases: []string{"ws", "workspaces"},
		Short:   "Manage and inspect per-target workspaces",
	}
	cmd.AddCommand(newWorkspaceListCmd(), newWorkspaceShowCmd(), newWorkspaceDeleteCmd())
	return cmd
}

func newWorkspaceListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List all workspaces",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			wss, err := app.wsm.List()
			if err != nil {
				return err
			}
			if len(wss) == 0 {
				fmt.Println(mutedStyle.Render("no workspaces yet — run a recon scan to create one"))
				return nil
			}
			fmt.Println(headerStyle.Render("Workspaces"))
			for _, w := range wss {
				fmt.Printf("  %s  %s\n",
					valueStyle.Render(padRight(w.Name, 28)),
					mutedStyle.Render(w.Target))
			}
			return nil
		},
	}
}

func newWorkspaceShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show scan history for a workspace",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ws, err := app.wsm.Open(args[0], args[0])
			if err != nil {
				return err
			}
			st, err := store.Open(ws.DBPath())
			if err != nil {
				return err
			}
			defer st.Close()
			scans, err := st.AllScans()
			if err != nil {
				return err
			}
			fmt.Println(headerStyle.Render("Workspace ") + valueStyle.Render(ws.Name))
			fmt.Println(mutedStyle.Render("Path: " + ws.Path))
			if len(scans) == 0 {
				fmt.Println(mutedStyle.Render("no scans recorded"))
				return nil
			}
			fmt.Println("\n" + headerStyle.Render("Scans"))
			for _, s := range scans {
				fmt.Printf("  #%d  %s  %s  %s  %s\n",
					s.ID, padRight(string(s.Mode), 8),
					padRight(string(s.Status), 10),
					s.StartedAt.Format("2006-01-02 15:04"),
					mutedStyle.Render(s.Target))
			}
			return nil
		},
	}
}

func newWorkspaceDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name>",
		Aliases: []string{"rm"},
		Short:   "Delete a workspace and all its data",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := app.wsm.Delete(args[0]); err != nil {
				return err
			}
			fmt.Println(okStyle.Render("deleted workspace " + args[0]))
			return nil
		},
	}
}
