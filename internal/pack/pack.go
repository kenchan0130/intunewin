package pack

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/kenchan0130/intunewin/internal/crypto"
	"github.com/kenchan0130/intunewin/internal/metadata"
)

// PackReaderFromZip creates an intunewin package from a zip stream.
// zipReader should contain a zip archive.
// name is the application name for metadata.
// setupFile is the setup file name within the content file.
// Returns an io.Reader containing the intunewin package.
func PackReaderFromZip(zipReader io.Reader, name, setupFile string) (io.Reader, error) {
	// Read all zip data
	sourceData, err := io.ReadAll(zipReader)
	if err != nil {
		return nil, fmt.Errorf("failed to read zip data: %w", err)
	}
	unencryptedSize := int64(len(sourceData))

	// Compute file digest before encryption
	fileDigest, err := crypto.ComputeFileDigest(bytes.NewReader(sourceData))
	if err != nil {
		return nil, fmt.Errorf("failed to compute file digest: %w", err)
	}

	// Generate encryption keys
	encKey, macKey, iv, err := crypto.GenerateKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate encryption keys: %w", err)
	}

	// Encrypt data
	encryptedBuf := new(bytes.Buffer)
	mac, err := crypto.Encrypt(bytes.NewReader(sourceData), encryptedBuf, encKey, macKey, iv)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Create encryption info
	encInfo := &crypto.EncryptionInfo{
		EncryptionKey:        encKey,
		MacKey:               macKey,
		InitializationVector: iv,
		Mac:                  mac,
		FileDigest:           fileDigest,
		ProfileIdentifier:    "ProfileVersion1",
		FileDigestAlgorithm:  "SHA256",
	}

	// Create ApplicationInfo with XML metadata
	appInfo := metadata.NewApplicationInfo(name, setupFile, unencryptedSize, encInfo)
	metaXML, err := appInfo.ToXML()
	if err != nil {
		return nil, fmt.Errorf("failed to create metadata XML: %w", err)
	}

	// Create final intunewin package (zip archive with proper structure)
	outputBuf := new(bytes.Buffer)
	outputZipWriter := zip.NewWriter(outputBuf)

	// Use current time for all files
	now := time.Now()

	// Add Detection.xml at IntuneWinPackage/Metadata/Detection.xml
	metaHeader := &zip.FileHeader{
		Name:     "IntuneWinPackage/Metadata/Detection.xml",
		Method:   zip.Deflate,
		Modified: now,
	}
	metaWriter, err := outputZipWriter.CreateHeader(metaHeader)
	if err != nil {
		outputZipWriter.Close()
		return nil, fmt.Errorf("failed to create metadata entry: %w", err)
	}
	if _, err := metaWriter.Write(metaXML); err != nil {
		outputZipWriter.Close()
		return nil, fmt.Errorf("failed to write metadata: %w", err)
	}

	// Add encrypted contents at IntuneWinPackage/Contents/IntunePackage.intunewin
	contentsHeader := &zip.FileHeader{
		Name:     "IntuneWinPackage/Contents/IntunePackage.intunewin",
		Method:   zip.Deflate,
		Modified: now,
	}
	contentsWriter, err := outputZipWriter.CreateHeader(contentsHeader)
	if err != nil {
		outputZipWriter.Close()
		return nil, fmt.Errorf("failed to create contents entry: %w", err)
	}
	if _, err := contentsWriter.Write(encryptedBuf.Bytes()); err != nil {
		outputZipWriter.Close()
		return nil, fmt.Errorf("failed to write contents: %w", err)
	}

	if err := outputZipWriter.Close(); err != nil {
		return nil, fmt.Errorf("failed to close zip writer: %w", err)
	}

	return bytes.NewReader(outputBuf.Bytes()), nil
}

// Pack creates an intunewin file from a source folder
func Pack(sourceFolder, outputFile string) error {
	// Check if source folder exists
	info, err := os.Stat(sourceFolder)
	if err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("source folder does not exist: %s", sourceFolder)
		}
		return fmt.Errorf("failed to access source folder: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", sourceFolder)
	}

	// Create output directory if it doesn't exist
	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}

	// Collect files from folder into FileEntry slice
	var files []struct {
		Path     string
		Content  io.Reader
		Mode     os.FileMode
		IsDir    bool
		Modified time.Time
	}
	err = filepath.Walk(sourceFolder, func(path string, fileInfo os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Get relative path
		relPath, err := filepath.Rel(sourceFolder, path)
		if err != nil {
			return err
		}

		// Skip root directory
		if relPath == "." {
			return nil
		}

		// Convert to slash path for zip
		relPath = filepath.ToSlash(relPath)

		if fileInfo.IsDir() {
			// Add directory entry
			files = append(files, struct {
				Path     string
				Content  io.Reader
				Mode     os.FileMode
				IsDir    bool
				Modified time.Time
			}{
				Path:     relPath,
				Mode:     fileInfo.Mode(),
				IsDir:    true,
				Modified: fileInfo.ModTime(),
			})
		} else {
			// Read file content
			content, err := os.ReadFile(path)
			if err != nil {
				return fmt.Errorf("failed to read file %s: %w", path, err)
			}

			files = append(files, struct {
				Path     string
				Content  io.Reader
				Mode     os.FileMode
				IsDir    bool
				Modified time.Time
			}{
				Path:     relPath,
				Content:  bytes.NewReader(content),
				Mode:     fileInfo.Mode(),
				IsDir:    false,
				Modified: fileInfo.ModTime(),
			})
		}

		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to walk source folder: %w", err)
	}

	// Create zip from files
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	for _, file := range files {
		if file.IsDir {
			header := &zip.FileHeader{
				Name:     file.Path + "/",
				Modified: file.Modified,
			}
			header.SetMode(file.Mode)
			_, err := zipWriter.CreateHeader(header)
			if err != nil {
				zipWriter.Close()
				return fmt.Errorf("failed to create directory entry %s: %w", file.Path, err)
			}
		} else {
			header := &zip.FileHeader{
				Name:     file.Path,
				Method:   zip.Deflate,
				Modified: file.Modified,
			}
			header.SetMode(file.Mode)

			writer, err := zipWriter.CreateHeader(header)
			if err != nil {
				zipWriter.Close()
				return fmt.Errorf("failed to create file entry %s: %w", file.Path, err)
			}

			if _, err := io.Copy(writer, file.Content); err != nil {
				zipWriter.Close()
				return fmt.Errorf("failed to write file content %s: %w", file.Path, err)
			}
		}
	}

	if err := zipWriter.Close(); err != nil {
		return fmt.Errorf("failed to close zip writer: %w", err)
	}

	// Determine name and setup file from source folder
	name := filepath.Base(sourceFolder)
	setupFile := name // Default to folder name, can be customized

	// Use PackReaderFromZip to create intunewin package
	intunewinReader, err := PackReaderFromZip(bytes.NewReader(zipBuf.Bytes()), name, setupFile)
	if err != nil {
		return fmt.Errorf("failed to create intunewin package: %w", err)
	}

	// Write to output file
	outFile, err := os.Create(outputFile)
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	defer outFile.Close()

	if _, err := io.Copy(outFile, intunewinReader); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}

	return nil
}
