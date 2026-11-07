package intunewin_test

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/kenchan0130/intunewin/internal/testutil"
	"github.com/kenchan0130/intunewin/pkg/intunewin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPackUnpackRoundTrip(t *testing.T) {
	content := testutil.MakeZip(t,
		testutil.ZipEntry{Name: "setup.exe", Content: "exe"},
		testutil.ZipEntry{Name: "config/settings.json", Content: `{"v":1}`},
	)
	var pkg bytes.Buffer
	require.NoError(t, intunewin.Pack(&pkg, bytes.NewReader(content), intunewin.PackOptions{SetupFile: "setup.exe", Name: "My App"}))

	info, err := intunewin.ReadInfo(bytes.NewReader(pkg.Bytes()), int64(pkg.Len()))
	require.NoError(t, err)
	assert.Equal(t, "My App", info.Name)
	assert.Equal(t, "setup.exe", info.SetupFile)
	assert.Equal(t, int64(len(content)), info.UnencryptedContentSize)
	assert.Len(t, info.EncryptionInfo.EncryptionKey, 32)

	var out bytes.Buffer
	info2, err := intunewin.Unpack(&out, bytes.NewReader(pkg.Bytes()), int64(pkg.Len()))
	require.NoError(t, err)
	assert.Equal(t, content, out.Bytes())
	assert.Equal(t, info, info2)
}

func TestPackDirUnpackDirRoundTrip(t *testing.T) {
	src := filepath.Join(t.TempDir(), "app")
	files := map[string]string{"setup.msi": "msi", "sub/a.txt": "a", "sub/b/c.txt": "c"}
	testutil.WriteFiles(t, src, files)
	pkg := filepath.Join(t.TempDir(), "app.intunewin")
	out := filepath.Join(t.TempDir(), "out")

	require.NoError(t, intunewin.PackDir(src, pkg, intunewin.PackDirOptions{}))
	require.NoError(t, intunewin.UnpackDir(pkg, out))
	for name, want := range files {
		got, err := os.ReadFile(filepath.Join(out, filepath.FromSlash(name)))
		require.NoError(t, err)
		assert.Equal(t, want, string(got))
	}
}

func TestErrorsAreReturnedNotPanics(t *testing.T) {
	bad := []byte("not a package")
	_, err := intunewin.ReadInfo(bytes.NewReader(bad), int64(len(bad)))
	require.Error(t, err)
	_, err = intunewin.Unpack(io.Discard, bytes.NewReader(bad), int64(len(bad)))
	require.Error(t, err)
	require.Error(t, intunewin.Pack(io.Discard, bytes.NewReader(nil), intunewin.PackOptions{}))
}

// The deprecated reader-based API keeps working.
func TestDeprecatedReaderAPI(t *testing.T) {
	content := testutil.MakeZip(t, testutil.ZipEntry{Name: "setup.exe", Content: "exe"})
	packed, err := intunewin.PackReader(bytes.NewReader(content), "app", "setup.exe")
	require.NoError(t, err)
	unpacked, err := intunewin.UnpackReader(packed)
	require.NoError(t, err)
	got, err := io.ReadAll(unpacked)
	require.NoError(t, err)
	assert.Equal(t, content, got)

	// Earlier versions accepted an empty setup file; it now defaults to the name.
	packed, err = intunewin.PackReader(bytes.NewReader(content), "app.exe", "")
	require.NoError(t, err)
	data, err := io.ReadAll(packed)
	require.NoError(t, err)
	info, err := intunewin.ReadInfo(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	assert.Equal(t, "app.exe", info.SetupFile)

	_, err = intunewin.UnpackReader(bytes.NewReader([]byte("x")))
	require.Error(t, err)
}

// patternReader yields n deterministic bytes without holding them in memory.
type patternReader struct{ n, off int64 }

func (r *patternReader) Read(p []byte) (int, error) {
	if r.off >= r.n {
		return 0, io.EOF
	}
	p = p[:min(int64(len(p)), r.n-r.off)]
	for i := range p {
		p[i] = byte((r.off + int64(i)) * 31 >> 3) //nolint:gosec // truncation is intended
	}
	r.off += int64(len(p))
	return len(p), nil
}

func allocated(f func()) uint64 {
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	f()
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// Memory use must not grow with the package size (Intune packages can be many GB).
func TestPackAndUnpackStreamWithBoundedMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("writes a large temporary file")
	}
	const size = 128 << 20
	const limit = 16 << 20
	pkgPath := filepath.Join(t.TempDir(), "big.intunewin")
	f, err := os.Create(pkgPath)
	require.NoError(t, err)
	defer f.Close()

	alloc := allocated(func() {
		require.NoError(t, intunewin.Pack(f, &patternReader{n: size}, intunewin.PackOptions{SetupFile: "setup.exe"}))
	})
	assert.Less(t, alloc, uint64(limit), "Pack allocated %d bytes for %d bytes of content", alloc, size)

	st, err := f.Stat()
	require.NoError(t, err)
	alloc = allocated(func() {
		info, err := intunewin.Unpack(io.Discard, f, st.Size())
		require.NoError(t, err)
		assert.Equal(t, int64(size), info.UnencryptedContentSize)
	})
	assert.Less(t, alloc, uint64(limit), "Unpack allocated %d bytes for %d bytes of content", alloc, size)
}
