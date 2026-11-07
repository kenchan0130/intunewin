// Package intunewin creates and extracts Microsoft Intune .intunewin packages.
//
// A package is a zip archive containing IntuneWinPackage/Metadata/Detection.xml and
// IntuneWinPackage/Contents/IntunePackage.intunewin, the latter being a zip archive of
// the application files encrypted with AES-256-CBC and authenticated with HMAC-SHA256.
//
// All functions stream their data: memory use does not depend on the package size.
// The format requires seeking, so temporary files about as large as the content are
// used: next to the output for PackDir and UnpackDir, and in os.TempDir (see TMPDIR)
// for Pack. Unpack reads its source twice instead.
package intunewin

import (
	"bytes"
	"fmt"
	"io"

	"github.com/kenchan0130/intunewin/internal/metadata"
	"github.com/kenchan0130/intunewin/internal/pack"
	"github.com/kenchan0130/intunewin/internal/unpack"
)

// PackOptions configures the Detection.xml of a package.
//
//   - Name is written to <Name>. Defaults to the base name of SetupFile.
//   - SetupFile is the setup file path relative to the package content root.
//     Only its file name is written to <SetupFile>.
type PackOptions = pack.Options

// PackDirOptions configures PackDir. In addition to PackOptions:
//
//   - Exclude lists glob patterns (path.Match syntax) matched against each path
//     relative to the source directory and against its base name.
//   - Overwrite allows replacing an existing output file.
//
// If SetupFile is empty, the first .msi, or else .exe, file at the top level of the
// source directory is used.
type PackDirOptions = pack.DirOptions

// Info is the content of a package's Detection.xml. EncryptionInfo holds the values
// the Microsoft Graph API expects as fileEncryptionInfo when uploading the content.
type Info = metadata.Info

// EncryptionInfo holds the encryption parameters of a package.
type EncryptionInfo = metadata.EncryptionInfo

// Pack builds a package from content, a zip archive of the application files, and
// writes it to dst. opts.SetupFile is required.
func Pack(dst io.Writer, content io.Reader, opts PackOptions) error {
	if err := pack.Write(dst, content, opts); err != nil {
		return fmt.Errorf("failed to pack: %w", err)
	}
	return nil
}

// PackDir packages the files in sourceDir into the file outputFile.
func PackDir(sourceDir, outputFile string, opts PackDirOptions) error {
	if err := pack.Dir(sourceDir, outputFile, opts); err != nil {
		return fmt.Errorf("failed to pack: %w", err)
	}
	return nil
}

// ReadInfo returns the Detection.xml of the package in src without decrypting it.
func ReadInfo(src io.ReaderAt, size int64) (*Info, error) {
	pkg, err := unpack.Open(src, size)
	if err != nil {
		return nil, fmt.Errorf("failed to read package: %w", err)
	}
	return pkg.Info(), nil
}

// Unpack verifies the package in src and writes its decrypted content, a zip archive,
// to dst.
//
// The HMAC is verified before anything is written to dst. The digest and size recorded
// in Detection.xml are checked as data is written; if Unpack returns an error, anything
// written to dst must be discarded.
func Unpack(dst io.Writer, src io.ReaderAt, size int64) (*Info, error) {
	pkg, err := unpack.Open(src, size)
	if err != nil {
		return nil, fmt.Errorf("failed to unpack: %w", err)
	}
	if err := pkg.Decrypt(dst); err != nil {
		return nil, fmt.Errorf("failed to unpack: %w", err)
	}
	return pkg.Info(), nil
}

// UnpackDir extracts the package file inputFile into outputDir.
func UnpackDir(inputFile, outputDir string) error {
	if err := unpack.Dir(inputFile, outputDir); err != nil {
		return fmt.Errorf("failed to unpack: %w", err)
	}
	return nil
}

// PackReader creates a package from a zip stream.
//
// Deprecated: Use Pack, which writes to an io.Writer without buffering the package in memory.
//
// For compatibility with earlier versions, an empty setupFile defaults to name.
func PackReader(zipReader io.Reader, name, setupFile string) (io.Reader, error) {
	if setupFile == "" {
		setupFile = name
	}
	var buf bytes.Buffer
	if err := Pack(&buf, zipReader, PackOptions{Name: name, SetupFile: setupFile}); err != nil {
		return nil, err
	}
	return &buf, nil
}

// UnpackReader extracts a package and returns its content as a zip stream.
//
// Deprecated: Use Unpack, which reads from an io.ReaderAt without buffering the package in memory.
func UnpackReader(input io.Reader) (io.Reader, error) {
	data, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}
	var buf bytes.Buffer
	if _, err := Unpack(&buf, bytes.NewReader(data), int64(len(data))); err != nil {
		return nil, err
	}
	return &buf, nil
}
