package unpack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/kenchan0130/intunewin/internal/pack"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnpack(t *testing.T) {
	// Create temporary test directory
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	packedFile := filepath.Join(tempDir, "test.intunewin")
	extractDir := filepath.Join(tempDir, "extracted")

	// Create source directory with test files
	require.NoError(t, os.MkdirAll(sourceDir, 0755))
	testContent := []byte("Hello, World!")
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "test.txt"), testContent, 0644))
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "subdir", "test2.txt"), []byte("Test file 2"), 0644))

	// Pack
	err := pack.Pack(sourceDir, packedFile)
	require.NoError(t, err)

	// Unpack
	err = Unpack(packedFile, extractDir)
	require.NoError(t, err)

	// Verify extracted files
	extractedFile := filepath.Join(extractDir, "test.txt")
	content, err := os.ReadFile(extractedFile)
	require.NoError(t, err)
	assert.Equal(t, testContent, content)

	// Verify subdirectory
	extractedFile2 := filepath.Join(extractDir, "subdir", "test2.txt")
	content2, err := os.ReadFile(extractedFile2)
	require.NoError(t, err)
	assert.Equal(t, []byte("Test file 2"), content2)
}

func TestUnpackNonExistentFile(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "nonexistent.intunewin")
	outputDir := filepath.Join(tempDir, "output")

	err := Unpack(inputFile, outputDir)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestUnpackInvalidFile(t *testing.T) {
	tempDir := t.TempDir()
	inputFile := filepath.Join(tempDir, "invalid.intunewin")
	outputDir := filepath.Join(tempDir, "output")

	// Create an invalid file
	require.NoError(t, os.WriteFile(inputFile, []byte("not a valid intunewin file"), 0644))

	err := Unpack(inputFile, outputDir)
	assert.Error(t, err)
}
