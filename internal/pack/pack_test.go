package pack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPack(t *testing.T) {
	// Create temporary test directory
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "source")
	outputDir := filepath.Join(tempDir, "output")

	// Create source directory with test files
	require.NoError(t, os.MkdirAll(sourceDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "test.txt"), []byte("Hello, World!"), 0600))
	require.NoError(t, os.MkdirAll(filepath.Join(sourceDir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(sourceDir, "subdir", "test2.txt"), []byte("Test file 2"), 0600))

	// Pack
	outputFile := filepath.Join(outputDir, "test.intunewin")
	err := Pack(sourceDir, outputFile)
	require.NoError(t, err)

	// Verify output file exists
	info, err := os.Stat(outputFile)
	require.NoError(t, err)
	assert.Greater(t, info.Size(), int64(0))
}

func TestPackNonExistentSource(t *testing.T) {
	tempDir := t.TempDir()
	sourceDir := filepath.Join(tempDir, "nonexistent")
	outputFile := filepath.Join(tempDir, "output.intunewin")

	err := Pack(sourceDir, outputFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not exist")
}

func TestPackFileInsteadOfDirectory(t *testing.T) {
	tempDir := t.TempDir()
	sourceFile := filepath.Join(tempDir, "test.txt")
	require.NoError(t, os.WriteFile(sourceFile, []byte("test"), 0600))

	outputFile := filepath.Join(tempDir, "output.intunewin")

	err := Pack(sourceFile, outputFile)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not a directory")
}
