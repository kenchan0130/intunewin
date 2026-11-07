package pack

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Dir checks for an existing output early, but another process may create it while
// the package is being written. publish must still refuse to replace it.
func TestPublish_DoesNotReplaceFileCreatedConcurrently(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	out := filepath.Join(dir, "out.intunewin")
	require.NoError(t, os.WriteFile(tmp, []byte("new"), 0o600))
	require.NoError(t, os.WriteFile(out, []byte("other"), 0o600))

	assert.ErrorContains(t, publish(tmp, out, false), "already exists")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "other", string(data))

	require.NoError(t, publish(tmp, out, true))
	data, err = os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "new", string(data))
	assert.NoFileExists(t, tmp)
}

func TestPublish_MovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	tmp := filepath.Join(dir, "tmp")
	out := filepath.Join(dir, "out.intunewin")
	require.NoError(t, os.WriteFile(tmp, []byte("new"), 0o600))

	require.NoError(t, publish(tmp, out, false))
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "new", string(data))
	assert.NoFileExists(t, tmp)
}
