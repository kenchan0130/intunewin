// Package testutil provides helpers shared by tests.
package testutil

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// ZipEntry describes one entry of a zip archive built by MakeZip.
type ZipEntry struct {
	Name    string
	Content string
	Mode    fs.FileMode // zero means default
}

// MakeZip builds a zip archive in memory.
func MakeZip(t testing.TB, entries ...ZipEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.Name, Method: zip.Deflate}
		if e.Mode != 0 {
			h.SetMode(e.Mode)
		}
		w, err := zw.CreateHeader(h)
		require.NoError(t, err)
		if e.Content != "" {
			_, err = w.Write([]byte(e.Content))
			require.NoError(t, err)
		}
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// ReadZip returns the entries of a zip archive keyed by name.
func ReadZip(t testing.TB, data []byte) map[string]*zip.File {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	out := make(map[string]*zip.File, len(zr.File))
	for _, f := range zr.File {
		out[f.Name] = f
	}
	return out
}

// ReadZipFile returns the content of a zip entry.
func ReadZipFile(t testing.TB, f *zip.File) []byte {
	t.Helper()
	rc, err := f.Open()
	require.NoError(t, err)
	defer rc.Close()
	data, err := io.ReadAll(rc)
	require.NoError(t, err)
	return data
}

// RewriteZip copies a zip archive, replacing the content of entries for which
// edit returns a non-nil value.
func RewriteZip(t testing.TB, data []byte, edit func(name string, content []byte) []byte) []byte {
	t.Helper()
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range zr.File {
		content := ReadZipFile(t, f)
		if replaced := edit(f.Name, content); replaced != nil {
			content = replaced
		}
		w, err := zw.CreateHeader(&zip.FileHeader{Name: f.Name, Method: f.Method})
		require.NoError(t, err)
		_, err = w.Write(content)
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

// WriteFiles creates files (and parent directories) under dir.
func WriteFiles(t testing.TB, dir string, files map[string]string) {
	t.Helper()
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
		require.NoError(t, os.WriteFile(p, []byte(content), 0o600))
	}
}

// Symlink creates a symbolic link or skips the test if that is not possible.
func Symlink(t testing.TB, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create symlink: %v", err)
	}
}

// ListFiles returns all paths (slash-separated, relative) under dir.
func ListFiles(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	require.NoError(t, filepath.WalkDir(dir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return fmt.Errorf("rel: %w", err)
		}
		if rel != "." {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	}))
	return out
}
