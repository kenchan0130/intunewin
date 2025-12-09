package intunewin

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/kenchan0130/intunewin/internal/pack"
	"github.com/kenchan0130/intunewin/internal/unpack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackAndUnpack(t *testing.T) {
	// Create temporary test directory
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	packedFile := filepath.Join(tempDir, "test.intunewin")
	extractDir := filepath.Join(tempDir, "extracted")

	// Create source directory with test files
	require.NoError(t, os.MkdirAll(sourceDir, 0755))
	testContent := []byte("Hello, World! This is a test file.")
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "test.txt"), testContent, 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "subdir"), 0755))
	testContent2 := []byte("Test file in subdirectory")
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "subdir", "test2.txt"), testContent2, 0600))

	// Pack
	err := pack.Pack(sourceDir, packedFile)
	require.NoError(t, err)

	// Verify packed file exists
	info, err := os.Stat(packedFile)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))

	// Unpack
	err = unpack.Unpack(packedFile, extractDir)
	require.NoError(t, err)

	// Verify extracted files
	extractedFile := filepath.Join(extractDir, "test.txt")
	content, err := os.ReadFile(extractedFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, content)

	extractedFile2 := filepath.Join(extractDir, "subdir", "test2.txt")
	content2, err := os.ReadFile(extractedFile2)
	require.NoError(t, err)
	assert.Equal(t, testContent2, content2)
}

func TestPackWithNonExistentSource(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "nonexistent")
	outputFile := filepath.Join(tempDir, "output.intunewin")

	err := pack.Pack(sourceDir, outputFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestUnpackWithNonExistentFile(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "nonexistent.intunewin")
	outputDir := filepath.Join(tempDir, "output")

	err := unpack.Unpack(inputFile, outputDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestPackReaderAndUnpackReader(t *testing.T) {
	// Create a zip archive in memory
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	// Add test.txt
	w1, err := zipWriter.Create("test.txt")
	require.NoError(t, err)
	_, err = w1.Write([]byte("Hello, World! This is test data for low-level API."))
	require.NoError(t, err)

	// Add subdir/
	_, err = zipWriter.Create("subdir/")
	require.NoError(t, err)

	// Add subdir/file2.txt
	w2, err := zipWriter.Create("subdir/file2.txt")
	require.NoError(t, err)
	_, err = w2.Write([]byte("File in subdirectory"))
	require.NoError(t, err)

	require.NoError(t, zipWriter.Close())

	// Pack using low-level API
	packedReader, err := PackReader(bytes.NewReader(zipBuf.Bytes()), "test", "test.txt")
	require.NoError(t, err)

	// Read packed data
	packedData, err := io.ReadAll(packedReader)
	require.NoError(t, err)
	assert.Greater(t, len(packedData), 0)

	// Unpack using low-level API
	unpackedZipReader, err := UnpackReader(bytes.NewReader(packedData))
	require.NoError(t, err)

	// Read unpacked zip data
	unpackedZipData, err := io.ReadAll(unpackedZipReader)
	require.NoError(t, err)

	// Verify it's a valid zip
	zipReader, err := zip.NewReader(bytes.NewReader(unpackedZipData), int64(len(unpackedZipData)))
	require.NoError(t, err)
	assert.Len(t, zipReader.File, 3)

	// Verify files
	assert.Equal(t, "test.txt", zipReader.File[0].Name)
	assert.Equal(t, "subdir/", zipReader.File[1].Name)
	assert.Equal(t, "subdir/file2.txt", zipReader.File[2].Name)
}

func TestPackReaderWithMinimalData(t *testing.T) {
	// Create minimal zip
	zipBuf := new(bytes.Buffer)
	zipWriter := zip.NewWriter(zipBuf)

	w, err := zipWriter.Create("minimal.txt")
	require.NoError(t, err)
	_, err = w.Write([]byte("x"))
	require.NoError(t, err)
	require.NoError(t, zipWriter.Close())

	packedReader, err := PackReader(bytes.NewReader(zipBuf.Bytes()), "minimal", "minimal.txt")
	require.NoError(t, err)

	packedData, err := io.ReadAll(packedReader)
	require.NoError(t, err)
	assert.Greater(t, len(packedData), 0)

	// Should be able to unpack minimal data
	unpackedZipReader, err := UnpackReader(bytes.NewReader(packedData))
	require.NoError(t, err)

	unpackedZipData, err := io.ReadAll(unpackedZipReader)
	require.NoError(t, err)

	// Verify it's a valid zip
	zipReader, err := zip.NewReader(bytes.NewReader(unpackedZipData), int64(len(unpackedZipData)))
	require.NoError(t, err)
	assert.Len(t, zipReader.File, 1)
}

func TestUnpackReaderWithInvalidData(t *testing.T) {
	invalidData := []byte("not a valid intunewin package")

	_, err := UnpackReader(bytes.NewReader(invalidData))
	assert.Error(t, err)
}
