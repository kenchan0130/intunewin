package main

import (
	"fmt"
	"io"
	"os"

	"github.com/kenchan0130/intunewin/pkg/intunewin"
	"github.com/spf13/cobra"
)

// Set by goreleaser via -ldflags.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

func newRootCmd() *cobra.Command {
	var quiet bool

	rootCmd := &cobra.Command{
		Use:   "intunewin",
		Short: "A CLI tool for creating and extracting intunewin files",
		Long: `intunewin is a CLI tool that allows you to create and extract .intunewin files.
It provides a simple interface for packaging folders into intunewin format
and extracting intunewin files back to folders.`,
		Version:       fmt.Sprintf("%s (commit %s, built %s)", version, commit, date),
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	rootCmd.PersistentFlags().BoolVarP(&quiet, "quiet", "q", false, "suppress progress messages")

	// Progress goes to stderr so stdout stays clean for scripting.
	progress := func(cmd *cobra.Command, format string, args ...any) {
		if !quiet {
			fmt.Fprintf(cmd.ErrOrStderr(), format, args...)
		}
	}

	var packOpts intunewin.PackDirOptions
	packCmd := &cobra.Command{
		Use:   "pack <source-folder> <output-file.intunewin>",
		Short: "Package a folder into an intunewin file",
		Long: `Pack creates an intunewin file from a source folder.
The source folder will be compressed, encrypted, and packaged
into the specified output file.

The setup file (--setup-file) is a path relative to the source folder.
If omitted, the first .msi file, or else the first .exe file, at the top
level of the source folder is used.`,
		Example: `  intunewin pack ./myapp ./dist/myapp.intunewin
  intunewin pack ./myapp ./dist/myapp.intunewin --setup-file install.cmd
  intunewin pack ./myapp ./dist/myapp.intunewin --exclude .DS_Store --exclude '*.log'`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			progress(cmd, "Packing %s to %s...\n", args[0], args[1])
			if err := intunewin.PackDir(args[0], args[1], packOpts); err != nil {
				return err //nolint:wrapcheck // already wrapped by the package
			}
			progress(cmd, "Successfully created %s\n", args[1])
			return nil
		},
	}
	packCmd.Flags().StringVarP(&packOpts.SetupFile, "setup-file", "s", "", "setup file, relative to the source folder (default: first .msi or .exe)")
	packCmd.Flags().StringVarP(&packOpts.Name, "name", "n", "", "application name written to Detection.xml (default: setup file name)")
	packCmd.Flags().StringArrayVarP(&packOpts.Exclude, "exclude", "e", nil, "glob pattern of files to exclude; a trailing / matches directories only (repeatable)")
	packCmd.Flags().BoolVarP(&packOpts.Overwrite, "force", "f", false, "overwrite the output file if it exists")

	unpackCmd := &cobra.Command{
		Use:   "unpack <input-file.intunewin> <output-folder>",
		Short: "Extract an intunewin file to a folder",
		Long: `Unpack extracts an intunewin file to a specified folder.
The file will be verified, decrypted, decompressed, and extracted
to the output folder.`,
		Example: `  intunewin unpack myapp.intunewin ./extracted`,
		Args:    cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			progress(cmd, "Unpacking %s to %s...\n", args[0], args[1])
			if err := intunewin.UnpackDir(args[0], args[1]); err != nil {
				return err //nolint:wrapcheck // already wrapped by the package
			}
			progress(cmd, "Successfully extracted to %s\n", args[1])
			return nil
		},
	}

	rootCmd.AddCommand(packCmd, unpackCmd)
	return rootCmd
}

func run(args []string, stdout, stderr io.Writer) int {
	cmd := newRootCmd()
	cmd.SetArgs(args)
	cmd.SetOut(stdout)
	cmd.SetErr(stderr)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	return 0
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}
