package unpack

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kenchan0130/intunewin/internal/crypto"
	"github.com/kenchan0130/intunewin/internal/metadata"
)

// UnpackReaderToZip extracts an intunewin package and returns a zip stream.
// input should contain the intunewin package (zip format with encrypted contents).
// Returns an io.Reader containing the decrypted zip archive.
func UnpackReaderToZip(input io.Reader) (io.Reader, error) {
	// Read all input data
	inputData, err := io.ReadAll(input)
	if err != nil {
		return nil, fmt.Errorf("failed to read input: %w", err)
	}

	// Open as zip archive
	zipReader, err := zip.NewReader(bytes.NewReader(inputData), int64(len(inputData)))
	if err != nil {
		return nil, fmt.Errorf("failed to open intunewin package: %w", err)
	}

	// Read metadata (Detection.xml) and encrypted contents
	var metaData []byte
	var encryptedData []byte

	for _, file := range zipReader.File {
		switch file.Name {
		case "IntuneWinPackage/Metadata/Detection.xml":
			metaData, err = readZipFileFromReader(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read Detection.xml: %w", err)
			}
		case "IntuneWinPackage/Contents/IntunePackage.intunewin":
			encryptedData, err = readZipFileFromReader(file)
			if err != nil {
				return nil, fmt.Errorf("failed to read encrypted contents: %w", err)
			}
		}
	}

	if metaData == nil {
		return nil, fmt.Errorf("Detection.xml not found in intunewin package")
	}
	if encryptedData == nil {
		return nil, fmt.Errorf("encrypted contents not found in intunewin package")
	}

	// Parse metadata (XML format)
	appInfo, err := metadata.FromXMLBytes(metaData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse Detection.xml: %w", err)
	}

	// Convert XML encryption info to crypto.EncryptionInfo
	encInfo, err := appInfo.EncryptionInfo.ToEncryptionInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to parse encryption info: %w", err)
	}

	// Decrypt contents
	encReader := bytes.NewReader(encryptedData)
	decryptedBuf := new(bytes.Buffer)
	if err := crypto.Decrypt(encReader, decryptedBuf, encInfo.EncryptionKey, encInfo.MacKey); err != nil {
		return nil, fmt.Errorf("failed to decrypt contents: %w", err)
	}

	return bytes.NewReader(decryptedBuf.Bytes()), nil
}

// readZipFileFromReader reads a file from a zip.File
func readZipFileFromReader(file *zip.File) ([]byte, error) {
	rc, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer rc.Close()

	return io.ReadAll(rc)
}

// Unpack extracts an intunewin file to a folder
func Unpack(inputFile, outputFolder string) error {
	// Check if input file exists
	if _, err := os.Stat(inputFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file does not exist: %s", inputFile)
		}
		return fmt.Errorf("failed to access input file: %w", err)
	}

	// Read input file
	inputData, err := os.ReadFile(inputFile)
	if err != nil {
		return fmt.Errorf("failed to read input file: %w", err)
	}

	// Use UnpackReaderToZip to get zip stream
	zipReader, err := UnpackReaderToZip(bytes.NewReader(inputData))
	if err != nil {
		return fmt.Errorf("failed to unpack: %w", err)
	}

	// Read zip data
	zipData, err := io.ReadAll(zipReader)
	if err != nil {
		return fmt.Errorf("failed to read zip data: %w", err)
	}

	// Parse zip
	zipBytesReader := bytes.NewReader(zipData)
	zipContentReader, err := zip.NewReader(zipBytesReader, int64(len(zipData)))
	if err != nil {
		return fmt.Errorf("failed to read zip: %w", err)
	}

	// Create output directory
	if err := os.MkdirAll(outputFolder, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Extract files
	for _, file := range zipContentReader.File {
		destPath := filepath.Join(outputFolder, file.Name)

		// Check for directory traversal
		cleanOutput := filepath.Clean(outputFolder) + string(os.PathSeparator)
		if !strings.HasPrefix(destPath, cleanOutput) {
			return fmt.Errorf("invalid file path: %s", file.Name)
		}

		if file.FileInfo().IsDir() {
			// Create directory
			if err := os.MkdirAll(destPath, file.Mode()); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", file.Name, err)
			}
		} else {
			// Create parent directories
			if err := os.MkdirAll(filepath.Dir(destPath), 0755); err != nil {
				return fmt.Errorf("failed to create parent directory for %s: %w", file.Name, err)
			}

			// Write file
			destFile, err := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
			if err != nil {
				return fmt.Errorf("failed to create file %s: %w", file.Name, err)
			}

			rc, err := file.Open()
			if err != nil {
				destFile.Close()
				return fmt.Errorf("failed to open file %s: %w", file.Name, err)
			}

			if _, err := io.Copy(destFile, rc); err != nil {
				rc.Close()
				destFile.Close()
				return fmt.Errorf("failed to write file %s: %w", file.Name, err)
			}
			rc.Close()
			destFile.Close()
		}
	}

	return nil
}
