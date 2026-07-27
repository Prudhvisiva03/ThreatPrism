package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/threatprism/threatprism/internal/core/target"
	"github.com/threatprism/threatprism/internal/store"
	"github.com/threatprism/threatprism/pkg/models"
)

func newNoteCmd() *cobra.Command {
	var tags string

	cmd := &cobra.Command{
		Use:   "note <target> <asset_url> <text>",
		Short: "Add an investigation notebook entry to an asset",
		Long:  "Attaches an investigation note and optional tags to a target asset in the workspace notebook.",
		Args:  cobra.ExactArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := target.Parse(args[0])
			if err != nil {
				return err
			}

			assetURL := args[1]
			text := args[2]

			ws, err := app.wsm.Open(t.Host, t.URL)
			if err != nil {
				return err
			}
			st, err := store.Open(ws.DBPath())
			if err != nil {
				return err
			}
			defer st.Close()

			var tagList []string
			if tags != "" {
				tagList = strings.Split(tags, ",")
			}

			note := &models.Note{
				Target:   t.Host,
				AssetURL: assetURL,
				Text:     text,
				Tags:     tagList,
			}

			if err := st.SaveNote(note); err != nil {
				return err
			}

			fmt.Println(okStyle.Render("✓ Note added to investigation notebook for " + assetURL))
			return nil
		},
	}

	cmd.Flags().StringVarP(&tags, "tags", "t", "", "comma-separated tags (e.g. interesting,admin,auth)")
	return cmd
}
