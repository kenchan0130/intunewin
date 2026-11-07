package pack_test

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/kenchan0130/intunewin/internal/crypto"
	"github.com/kenchan0130/intunewin/internal/metadata"
	"github.com/kenchan0130/intunewin/internal/pack"
	"github.com/kenchan0130/intunewin/internal/testutil"
	"github.com/kenchan0130/intunewin/internal/unpack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// packed is a package produced by pack.Dir, opened for inspection.
type packed struct {
	outer   map[string]*zip.File
	info    *metadata.Info
	content map[string]*zip.File // entries of the decrypted inner zip
}

func packDir(t *testing.T, src string, opts pack.DirOptions) packed {
	t.Helper()
	out := filepath.Join(t.TempDir(), "out.intunewin")
	require.NoError(t, pack.Dir(src, out, opts))
	return inspect(t, out)
}

func inspect(t *testing.T, file string) packed {
	t.Helper()
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	pkg, err := unpack.Open(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	var inner bytes.Buffer
	require.NoError(t, pkg.Decrypt(&inner))
	return packed{
		outer:   testutil.ReadZip(t, data),
		info:    pkg.Info(),
		content: testutil.ReadZip(t, inner.Bytes()),
	}
}

func names(m map[string]*zip.File) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func newSource(t *testing.T, files map[string]string) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "myapp")
	require.NoError(t, os.Mkdir(src, 0o755))
	testutil.WriteFiles(t, src, files)
	return src
}

// --- Package format ---

func TestDir_PackageLayout(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": "exe", "sub/data.txt": "data"})
	out := filepath.Join(t.TempDir(), "out.intunewin")
	require.NoError(t, pack.Dir(src, out, pack.DirOptions{}))

	raw, err := os.ReadFile(out)
	require.NoError(t, err)
	outer := testutil.ReadZip(t, raw)
	assert.Equal(t, []string{metadata.ContentPath, metadata.DetectionPath}, names(outer),
		"the outer zip contains exactly Detection.xml and the encrypted content")
	for name, f := range outer {
		assert.Equal(t, zip.Store, f.Method, "outer entry %s must be stored uncompressed", name)
	}

	// Encrypted content: [HMAC][IV][ciphertext] consistent with Detection.xml.
	info, err := metadata.Parse(testutil.ReadZipFile(t, outer[metadata.DetectionPath]))
	require.NoError(t, err)
	enc := testutil.ReadZipFile(t, outer[metadata.ContentPath])
	ei := info.EncryptionInfo
	assert.Equal(t, ei.Mac, enc[:crypto.MacSize], "Detection.xml Mac equals the HMAC in the content")
	assert.Equal(t, ei.InitializationVector, enc[crypto.MacSize:crypto.HeaderSize], "Detection.xml IV equals the IV in the content")
	assert.Equal(t, crypto.EncryptedSize(info.UnencryptedContentSize), int64(len(enc)))

	var inner bytes.Buffer
	require.NoError(t, crypto.Decrypt(&inner, bytes.NewReader(enc), ei.EncryptionKey))
	digest := sha256.Sum256(inner.Bytes())
	assert.Equal(t, digest[:], ei.FileDigest, "FileDigest is the SHA256 of the unencrypted inner zip")
	assert.Equal(t, int64(inner.Len()), info.UnencryptedContentSize, "UnencryptedContentSize is the size of the inner zip")

	assert.Equal(t, metadata.ToolVersion, info.ToolVersion)
	assert.Equal(t, metadata.ContentFileName, info.FileName)
	assert.Equal(t, metadata.ProfileIdentifier, ei.ProfileIdentifier)
	assert.Equal(t, metadata.FileDigestAlgorithm, ei.FileDigestAlgorithm)
}

func TestDir_KeysAreUniquePerPackage(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": "exe"})
	a := packDir(t, src, pack.DirOptions{})
	b := packDir(t, src, pack.DirOptions{})
	assert.NotEqual(t, a.info.EncryptionInfo.EncryptionKey, b.info.EncryptionInfo.EncryptionKey)
	assert.NotEqual(t, a.info.EncryptionInfo.InitializationVector, b.info.EncryptionInfo.InitializationVector)
}

func TestDir_ContentMatchesSourceFolder(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": "exe", "sub/data.txt": "data", "sub/deeper/x.bin": "x"})
	require.NoError(t, os.Chmod(filepath.Join(src, "setup.exe"), 0o755))

	p := packDir(t, src, pack.DirOptions{})
	assert.Equal(t, []string{"setup.exe", "sub/", "sub/data.txt", "sub/deeper/", "sub/deeper/x.bin"}, names(p.content))
	assert.Equal(t, "data", string(testutil.ReadZipFile(t, p.content["sub/data.txt"])))
	assert.Equal(t, zip.Deflate, p.content["sub/data.txt"].Method, "inner entries are compressed")
	if runtime.GOOS != "windows" {
		assert.Equal(t, fs.FileMode(0o755), p.content["setup.exe"].Mode(), "file permissions are preserved")
	}
}

// --- Detection.xml Name / SetupFile ---

func TestDir_SetupFileAutoDetection(t *testing.T) {
	tests := map[string]struct {
		files map[string]string
		want  string
	}{
		"msi preferred over exe": {map[string]string{"a.exe": "", "b.msi": "", "c.txt": ""}, "b.msi"},
		"exe when no msi":        {map[string]string{"z.exe": "", "c.txt": ""}, "z.exe"},
		"case insensitive":       {map[string]string{"SETUP.EXE": ""}, "SETUP.EXE"},
		"first in name order":    {map[string]string{"b.exe": "", "a.exe": ""}, "a.exe"},
		"top level only":         {map[string]string{"sub/deep.msi": "", "top.exe": ""}, "top.exe"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p := packDir(t, newSource(t, tt.files), pack.DirOptions{})
			assert.Equal(t, tt.want, p.info.SetupFile)
			assert.Equal(t, tt.want, p.info.Name, "Name defaults to the setup file name")
		})
	}
}

func TestDir_ExplicitSetupFileAndName(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": "", "scripts/install.cmd": ""})

	p := packDir(t, src, pack.DirOptions{Options: pack.Options{SetupFile: filepath.FromSlash("scripts/install.cmd")}})
	assert.Equal(t, "install.cmd", p.info.SetupFile, "only the file name is recorded, as the reference implementation does")
	assert.Equal(t, "install.cmd", p.info.Name)

	p = packDir(t, src, pack.DirOptions{Options: pack.Options{SetupFile: "setup.exe", Name: "My App"}})
	assert.Equal(t, "setup.exe", p.info.SetupFile)
	assert.Equal(t, "My App", p.info.Name)
}

func TestDir_SetupFileErrors(t *testing.T) {
	src := newSource(t, map[string]string{"readme.txt": "", "sub/a.txt": ""})
	out := filepath.Join(t.TempDir(), "out.intunewin")

	tests := map[string]struct {
		setup string
		want  string
	}{
		"none detectable": {"", "no .msi or .exe file found"},
		"missing":         {"nope.exe", "setup file not found"},
		"outside":         {"../other/setup.exe", "relative path inside the source folder"},
		"absolute":        {filepath.Join(src, "readme.txt"), "relative path inside the source folder"},
		"directory":       {"sub", "not a regular file"},
	}
	for name, tt := range tests {
		err := pack.Dir(src, out, pack.DirOptions{Options: pack.Options{SetupFile: tt.setup}})
		assert.ErrorContains(t, err, tt.want, name)
	}
	assert.NoFileExists(t, out)
}

// --- Source folder handling ---

func TestDir_SourceErrors(t *testing.T) {
	tmp := t.TempDir()
	file := filepath.Join(tmp, "file.txt")
	require.NoError(t, os.WriteFile(file, nil, 0o600))
	empty := filepath.Join(tmp, "empty")
	require.NoError(t, os.Mkdir(empty, 0o755))
	out := filepath.Join(tmp, "out.intunewin")

	assert.ErrorContains(t, pack.Dir(filepath.Join(tmp, "missing"), out, pack.DirOptions{}), "does not exist")
	assert.ErrorContains(t, pack.Dir(file, out, pack.DirOptions{}), "not a directory")
	assert.ErrorContains(t, pack.Dir(empty, out, pack.DirOptions{Options: pack.Options{SetupFile: "x"}}), "not found")
}

func TestDir_RejectsFolderWithoutFiles(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": ""})
	err := pack.Dir(src, filepath.Join(t.TempDir(), "o.intunewin"), pack.DirOptions{Exclude: []string{"*.exe"}, Options: pack.Options{SetupFile: "setup.exe"}})
	assert.ErrorContains(t, err, "no files")
}

func TestDir_SymlinkedSourceFolderIsFollowed(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": "exe", "sub/a.txt": "a"})
	link := filepath.Join(t.TempDir(), "link")
	testutil.Symlink(t, src, link)

	p := packDir(t, link, pack.DirOptions{})
	assert.Equal(t, []string{"setup.exe", "sub/", "sub/a.txt"}, names(p.content))
}

func TestDir_SymlinkToFileInsideSourceIsStoredAsRegularFile(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": "exe", "real.txt": "hello"})
	testutil.Symlink(t, "real.txt", filepath.Join(src, "link.txt"))

	p := packDir(t, src, pack.DirOptions{})
	f := p.content["link.txt"]
	require.NotNil(t, f)
	assert.True(t, f.Mode().IsRegular(), "mode %v must not carry the symlink bit", f.Mode())
	assert.Equal(t, "hello", string(testutil.ReadZipFile(t, f)))
}

func TestDir_RejectsSymlinkOutsideSource(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": ""})
	outside := filepath.Join(t.TempDir(), "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("secret"), 0o600))
	testutil.Symlink(t, outside, filepath.Join(src, "link.txt"))

	err := pack.Dir(src, filepath.Join(t.TempDir(), "o.intunewin"), pack.DirOptions{})
	assert.ErrorContains(t, err, "outside the source folder")
}

func TestDir_RejectsSymlinkToDirectory(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": "", "real/a.txt": ""})
	testutil.Symlink(t, "real", filepath.Join(src, "linkdir"))

	err := pack.Dir(src, filepath.Join(t.TempDir(), "o.intunewin"), pack.DirOptions{})
	assert.ErrorContains(t, err, "symbolic links to directories are not supported")
}

// --- Exclusion ---

func TestDir_Exclude(t *testing.T) {
	src := newSource(t, map[string]string{
		"setup.exe": "", ".DS_Store": "", "sub/.DS_Store": "", "logs/a.log": "", "sub/keep.txt": "", "sub/debug.log": "",
	})
	p := packDir(t, src, pack.DirOptions{Exclude: []string{".DS_Store", "logs", "sub/*.log"}})
	assert.Equal(t, []string{"setup.exe", "sub/", "sub/keep.txt"}, names(p.content))
}

func TestDir_ExcludeErrors(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": ""})
	out := filepath.Join(t.TempDir(), "o.intunewin")
	assert.ErrorContains(t, pack.Dir(src, out, pack.DirOptions{Exclude: []string{"["}}), "invalid exclude pattern")
	assert.ErrorContains(t, pack.Dir(src, out, pack.DirOptions{Exclude: []string{"*.exe"}, Options: pack.Options{SetupFile: "setup.exe"}}), "no files")

	src = newSource(t, map[string]string{"setup.exe": "", "other.txt": ""})
	assert.ErrorContains(t, pack.Dir(src, out, pack.DirOptions{Exclude: []string{"*.exe"}, Options: pack.Options{SetupFile: "setup.exe"}}), "excluded")
}

// --- Output handling ---

func TestDir_OutputInsideSourceIsNotPacked(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": ""})
	out := filepath.Join(src, "dist", "app.intunewin")

	require.NoError(t, pack.Dir(src, out, pack.DirOptions{}))
	// Re-packing must not include the previous output.
	require.NoError(t, pack.Dir(src, out, pack.DirOptions{Overwrite: true}))
	p := inspect(t, out)
	assert.Equal(t, []string{"dist/", "setup.exe"}, names(p.content))
}

func TestDir_RefusesToOverwriteUnlessAllowed(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": ""})
	out := filepath.Join(t.TempDir(), "o.intunewin")
	require.NoError(t, os.WriteFile(out, []byte("keep me"), 0o600))

	assert.ErrorContains(t, pack.Dir(src, out, pack.DirOptions{}), "already exists")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "keep me", string(data))

	require.NoError(t, pack.Dir(src, out, pack.DirOptions{Overwrite: true}))
	inspect(t, out)
}

func TestDir_CreatesOutputDirectory(t *testing.T) {
	src := newSource(t, map[string]string{"setup.exe": ""})
	out := filepath.Join(t.TempDir(), "a", "b", "o.intunewin")
	require.NoError(t, pack.Dir(src, out, pack.DirOptions{}))
	assert.FileExists(t, out)
}

func TestDir_FailureLeavesNoPartialOutput(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires POSIX permissions and a non-root user")
	}
	src := newSource(t, map[string]string{"setup.exe": "", "unreadable.txt": "x"})
	require.NoError(t, os.Chmod(filepath.Join(src, "unreadable.txt"), 0o000))
	outDir := t.TempDir()
	out := filepath.Join(outDir, "o.intunewin")
	require.NoError(t, os.WriteFile(out, []byte("previous"), 0o600))

	err := pack.Dir(src, out, pack.DirOptions{Overwrite: true})
	require.ErrorContains(t, err, "unreadable.txt")
	data, err := os.ReadFile(out)
	require.NoError(t, err)
	assert.Equal(t, "previous", string(data), "a failed pack must not replace the existing output")
	assert.Equal(t, []string{"o.intunewin"}, testutil.ListFiles(t, outDir), "no temporary files are left behind")
}

func TestDir_OutputPermissionsFollowUmask(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	src := newSource(t, map[string]string{"setup.exe": ""})
	dir := t.TempDir()
	out := filepath.Join(dir, "o.intunewin")
	require.NoError(t, pack.Dir(src, out, pack.DirOptions{}))

	ref, err := os.Create(filepath.Join(dir, "ref"))
	require.NoError(t, err)
	require.NoError(t, ref.Close())
	want, err := os.Stat(ref.Name())
	require.NoError(t, err)
	got, err := os.Stat(out)
	require.NoError(t, err)
	assert.Equal(t, want.Mode().Perm(), got.Mode().Perm(), "same permissions as a file created by os.Create")
}

func TestDir_TemporaryFilesStayNextToOutputAndAreRemoved(t *testing.T) {
	// An unusable os.TempDir (e.g. a full /tmp) must not matter: temporary files go next to the output.
	for _, env := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(env, filepath.Join(t.TempDir(), "missing"))
	}
	src := newSource(t, map[string]string{"setup.exe": "x"})
	outDir := t.TempDir()

	require.NoError(t, pack.Dir(src, filepath.Join(outDir, "o.intunewin"), pack.DirOptions{}))
	assert.Equal(t, []string{"o.intunewin"}, testutil.ListFiles(t, outDir), "no temporary files are left behind")
	// Removal on failure is covered by TestDir_FailureLeavesNoPartialOutput.
}

// --- Write (stream API) ---

func TestWrite_RequiresSetupFile(t *testing.T) {
	err := pack.Write(&bytes.Buffer{}, bytes.NewReader(testutil.MakeZip(t, testutil.ZipEntry{Name: "a"})), pack.Options{})
	assert.ErrorContains(t, err, "setup file is required")
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, os.ErrClosed }

func TestWrite_RemovesTemporaryFileOnFailure(t *testing.T) {
	sysTmp := t.TempDir()
	for _, env := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(env, sysTmp)
	}
	err := pack.Write(&bytes.Buffer{}, failingReader{}, pack.Options{SetupFile: "setup.exe"})
	require.ErrorIs(t, err, os.ErrClosed)
	assert.Empty(t, testutil.ListFiles(t, sysTmp))
}

func TestWrite_SetupFileIsRecordedByName(t *testing.T) {
	content := testutil.MakeZip(t, testutil.ZipEntry{Name: "bin/setup.exe", Content: "exe"})
	var out bytes.Buffer
	require.NoError(t, pack.Write(&out, bytes.NewReader(content), pack.Options{SetupFile: "bin/setup.exe"}))
	pkg, err := unpack.Open(bytes.NewReader(out.Bytes()), int64(out.Len()))
	require.NoError(t, err)
	assert.Equal(t, "setup.exe", pkg.Info().SetupFile)
	assert.Equal(t, "setup.exe", pkg.Info().Name)
}

func TestWrite_ContentIsPassedThrough(t *testing.T) {
	content := testutil.MakeZip(t, testutil.ZipEntry{Name: "setup.exe", Content: "exe"})
	var out bytes.Buffer
	require.NoError(t, pack.Write(&out, bytes.NewReader(content), pack.Options{SetupFile: "setup.exe"}))

	pkg, err := unpack.Open(bytes.NewReader(out.Bytes()), int64(out.Len()))
	require.NoError(t, err)
	var inner bytes.Buffer
	require.NoError(t, pkg.Decrypt(&inner))
	assert.Equal(t, content, inner.Bytes(), "the content zip is encrypted as-is")
	assert.Equal(t, "setup.exe", pkg.Info().Name)
}
