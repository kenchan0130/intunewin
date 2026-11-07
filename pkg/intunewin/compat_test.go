package intunewin_test

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/kenchan0130/intunewin/internal/testutil"
	"github.com/kenchan0130/intunewin/pkg/intunewin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The fixture was created on Windows 11 with Microsoft's IntuneWinAppUtil 1.8.7
// (FileVersion 6.2509.50.0, SHA256 c1ba45b5...671f6) from a folder containing
// install.cmd and sub\data.txt:
//
//	IntuneWinAppUtil.exe -c .\sample -s install.cmd -o .\out -q
const fixture = "../../testdata/IntuneWinAppUtil/install.intunewin"

func TestIntuneWinAppUtilPackageIsReadable(t *testing.T) {
	f, err := os.Open(fixture)
	require.NoError(t, err)
	defer f.Close()
	st, err := f.Stat()
	require.NoError(t, err)

	info, err := intunewin.ReadInfo(f, st.Size())
	require.NoError(t, err)
	assert.Equal(t, "1.8.7.0", info.ToolVersion)
	assert.Equal(t, "install.cmd", info.Name, "IntuneWinAppUtil names the app after the setup file")
	assert.Equal(t, "install.cmd", info.SetupFile)

	out := t.TempDir()
	require.NoError(t, intunewin.UnpackDir(fixture, out))
	assert.Equal(t, []string{"install.cmd", "sub", "sub/data.txt"}, testutil.ListFiles(t, out))
	data, err := os.ReadFile(filepath.Join(out, "sub", "data.txt"))
	require.NoError(t, err)
	assert.Equal(t, "data\r\n", string(data))
}

func TestPackMatchesIntuneWinAppUtilLayout(t *testing.T) {
	src := t.TempDir()
	testutil.WriteFiles(t, src, map[string]string{"install.cmd": "@echo off\r\necho hello\r\n", "sub/data.txt": "data\r\n"})
	out := filepath.Join(t.TempDir(), "install.intunewin")
	require.NoError(t, intunewin.PackDir(src, out, intunewin.PackDirOptions{Options: intunewin.PackOptions{SetupFile: "install.cmd"}}))

	want := outerEntries(t, fixture)
	got := outerEntries(t, out)
	require.Len(t, got, len(want))
	for i := range want {
		require.Equal(t, want[i].Name, got[i].Name, "entry %d", i)
		assert.Equal(t, want[i].Method, got[i].Method, "entry %s", want[i].Name)
	}

	// Detection.xml is byte-for-byte the same except for the per-package values.
	values := regexp.MustCompile(`>[^<>]*</(UnencryptedContentSize|EncryptionKey|MacKey|InitializationVector|Mac|FileDigest)>`)
	normalize := func(f *zip.File) string { return values.ReplaceAllString(string(testutil.ReadZipFile(t, f)), "></$1>") }
	assert.Equal(t, normalize(want[1]), normalize(got[1]))
}

func outerEntries(t *testing.T, file string) []*zip.File {
	t.Helper()
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	return zr.File
}
