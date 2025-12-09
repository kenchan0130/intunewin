package main

import (
	"fmt"
	"os"

	"github.com/kenchan0130/intunewin/internal/pack"
	"github.com/kenchan0130/intunewin/internal/unpack"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "intunewin",
	Short: "A CLI tool for creating and extracting intunewin files",
	Long: `intunewin is a CLI tool that allows you to create and extract .intunewin files.
It provides a simple interface for packaging folders into intunewin format
and extracting intunewin files back to folders.`,
}

var packCmd = &cobra.Command{
	Use:   "pack <source-folder> <output-file.intunewin>",
	Short: "Package a folder into an intunewin file",
	Long: `Pack creates an intunewin file from a source folder.
The source folder will be compressed, encrypted, and packaged
into the specified output file.

Example:
  intunewin pack ./myapp ./dist/myapp.intunewin`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		sourceFolder := args[0]
		outputFile := args[1]

		fmt.Printf("Packing %s to %s...\n", sourceFolder, outputFile)
		if err := pack.Pack(sourceFolder, outputFile); err != nil {
			return fmt.Errorf("failed to pack: %w", err)
		}
		fmt.Printf("Successfully created %s\n", outputFile)
		return nil
	},
}

var unpackCmd = &cobra.Command{
	Use:   "unpack <input-file.intunewin> <output-folder>",
	Short: "Extract an intunewin file to a folder",
	Long: `Unpack extracts an intunewin file to a specified folder.
The file will be decrypted, decompressed, and extracted
to the output folder.

Example:
  intunewin unpack myapp.intunewin ./extracted`,
	Args: cobra.ExactArgs(2),
	RunE: func(cmd *cobra.Command, args []string) error {
		inputFile := args[0]
		outputFolder := args[1]

		fmt.Printf("Unpacking %s to %s...\n", inputFile, outputFolder)
		if err := unpack.Unpack(inputFile, outputFolder); err != nil {
			return fmt.Errorf("failed to unpack: %w", err)
		}
		fmt.Printf("Successfully extracted to %s\n", outputFolder)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(packCmd)
	rootCmd.AddCommand(unpackCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
