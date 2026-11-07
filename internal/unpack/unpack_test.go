package unpack_test

import (
	"bytes"
	"encoding/base64"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/kenchan0130/intunewin/internal/metadata"
	"github.com/kenchan0130/intunewin/internal/pack"
	"github.com/kenchan0130/intunewin/internal/testutil"
	"github.com/kenchan0130/intunewin/internal/unpack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makePackage packs the given inner zip entries into an .intunewin package.
func makePackage(t *testing.T, entries ...testutil.ZipEntry) []byte {
	t.Helper()
	var out bytes.Buffer
	require.NoError(t, pack.Write(&out, bytes.NewReader(testutil.MakeZip(t, entries...)), pack.Options{SetupFile: "setup.exe"}))
	return out.Bytes()
}

func writePackage(t *testing.T, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "in.intunewin")
	require.NoError(t, os.WriteFile(p, data, 0o600))
	return p
}

func editDetection(t *testing.T, pkg []byte, edit func(string) string) []byte {
	t.Helper()
	return testutil.RewriteZip(t, pkg, func(name string, content []byte) []byte {
		if name == metadata.DetectionPath {
			return []byte(edit(string(content)))
		}
		return nil
	})
}

func editContent(t *testing.T, pkg []byte, edit func([]byte) []byte) []byte {
	t.Helper()
	return testutil.RewriteZip(t, pkg, func(name string, content []byte) []byte {
		if name == metadata.ContentPath {
			return edit(bytes.Clone(content))
		}
		return nil
	})
}

func replaceElement(xml, element, value string) string {
	start := strings.Index(xml, "<"+element+">") + len(element) + 2
	end := strings.Index(xml, "</"+element+">")
	return xml[:start] + value + xml[end:]
}

var sample = []testutil.ZipEntry{
	{Name: "setup.exe", Content: "exe"},
	{Name: "sub/"},
	{Name: "sub/data.txt", Content: "data"},
}

// --- Extraction ---

func TestDir_ExtractsFiles(t *testing.T) {
	in := writePackage(t, makePackage(t, sample...))
	out := filepath.Join(t.TempDir(), "a", "b")

	require.NoError(t, unpack.Dir(in, out))
	assert.Equal(t, []string{"setup.exe", "sub", "sub/data.txt"}, testutil.ListFiles(t, out))
	data, err := os.ReadFile(filepath.Join(out, "sub", "data.txt"))
	require.NoError(t, err)
	assert.Equal(t, "data", string(data))
}

func TestDir_OutputFolderForms(t *testing.T) {
	in := writePackage(t, makePackage(t, sample...))

	for _, rel := range []string{".", "./", "out", "./out", "out/../out2"} {
		t.Run(rel, func(t *testing.T) {
			dir := t.TempDir()
			t.Chdir(dir)
			require.NoError(t, unpack.Dir(in, rel))
			assert.FileExists(t, filepath.Join(dir, rel, "sub", "data.txt"))
		})
	}
}

func TestDir_InputErrors(t *testing.T) {
	out := t.TempDir()
	assert.ErrorContains(t, unpack.Dir(filepath.Join(out, "missing.intunewin"), out), "does not exist")

	bad := filepath.Join(t.TempDir(), "bad.intunewin")
	require.NoError(t, os.WriteFile(bad, []byte("not a zip"), 0o600))
	assert.ErrorContains(t, unpack.Dir(bad, out), "failed to open intunewin package")
}

// --- Safety of extraction ---

func TestDir_RejectsPathTraversal(t *testing.T) {
	for _, name := range []string{"../evil.txt", "a/../../evil.txt", "/abs.txt", `..\evil.txt`, "sub/../../evil.txt"} {
		t.Run(name, func(t *testing.T) {
			base := t.TempDir()
			out := filepath.Join(base, "out")
			in := writePackage(t, makePackage(t, testutil.ZipEntry{Name: name, Content: "x"}))

			assert.ErrorContains(t, unpack.Dir(in, out), "invalid file path")
			assert.NoFileExists(t, filepath.Join(base, "evil.txt"))
			assert.NoFileExists(t, "/abs.txt")
		})
	}
}

func TestDir_NormalizesEntryPaths(t *testing.T) {
	in := writePackage(t, makePackage(t,
		testutil.ZipEntry{Name: "x/../y.txt", Content: "y"},
		testutil.ZipEntry{Name: "./a//b.txt", Content: "b"},
		testutil.ZipEntry{Name: `win\style.txt`, Content: "w"},
	))
	out := t.TempDir()
	require.NoError(t, unpack.Dir(in, out))
	assert.FileExists(t, filepath.Join(out, "y.txt"))
	assert.FileExists(t, filepath.Join(out, "a", "b.txt"))
	assert.FileExists(t, filepath.Join(out, "win", "style.txt"))
}

func TestDir_IntoNonEmptyFolderOverwritesPackageFiles(t *testing.T) {
	out := t.TempDir()
	testutil.WriteFiles(t, out, map[string]string{"setup.exe": "old", "keep.txt": "keep"})
	require.NoError(t, unpack.Dir(writePackage(t, makePackage(t, sample...)), out))

	data, err := os.ReadFile(filepath.Join(out, "setup.exe"))
	require.NoError(t, err)
	assert.Equal(t, "exe", string(data))
	assert.FileExists(t, filepath.Join(out, "keep.txt"), "unrelated files are left alone")
}

func TestDir_TemporaryFilesStayOnOutputVolumeAndAreRemoved(t *testing.T) {
	base := t.TempDir()
	in := writePackage(t, makePackage(t, sample...))
	bad := writePackage(t, editContent(t, makePackage(t, sample...), func(b []byte) []byte { b[len(b)-1] ^= 1; return b }))
	// An unusable os.TempDir (e.g. a full /tmp) must not matter.
	for _, env := range []string{"TMPDIR", "TMP", "TEMP"} {
		t.Setenv(env, filepath.Join(t.TempDir(), "missing"))
	}

	require.NoError(t, unpack.Dir(in, filepath.Join(base, "out")))
	assert.Equal(t, []string{"out"}, topLevel(t, base), "no temporary file is left next to the output")

	require.Error(t, unpack.Dir(bad, filepath.Join(base, "out2")))
	assert.Equal(t, []string{"out"}, topLevel(t, base), "temporary files are removed on failure")
}

func topLevel(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Name())
	}
	return out
}

func TestDir_DoesNotFollowSymlinksOutOfOutputFolder(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside")
	require.NoError(t, os.Mkdir(outside, 0o755))
	out := filepath.Join(base, "out")
	require.NoError(t, os.Mkdir(out, 0o755))
	testutil.Symlink(t, outside, filepath.Join(out, "sub"))

	in := writePackage(t, makePackage(t, sample...))
	require.Error(t, unpack.Dir(in, out))
	assert.NoFileExists(t, filepath.Join(outside, "data.txt"))
}

func TestDir_ReplacesSymlinksInsteadOfWritingThroughThem(t *testing.T) {
	out := t.TempDir()
	victim := filepath.Join(out, "victim.txt")
	require.NoError(t, os.WriteFile(victim, []byte("keep"), 0o600))
	testutil.Symlink(t, "victim.txt", filepath.Join(out, "setup.exe"))

	in := writePackage(t, makePackage(t, sample...))
	require.NoError(t, unpack.Dir(in, out))

	data, err := os.ReadFile(victim)
	require.NoError(t, err)
	assert.Equal(t, "keep", string(data), "the link target must not be overwritten")
	info, err := os.Lstat(filepath.Join(out, "setup.exe"))
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular(), "the link is replaced by the extracted file")
}

func TestDir_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permissions")
	}
	in := writePackage(t, makePackage(t,
		testutil.ZipEntry{Name: "run.sh", Content: "#!/bin/sh", Mode: 0o755},
		testutil.ZipEntry{Name: "suid", Content: "x", Mode: 0o755 | fs.ModeSetuid | fs.ModeSetgid},
		testutil.ZipEntry{Name: "ro/", Mode: fs.ModeDir | 0o555},
		testutil.ZipEntry{Name: "ro/child.txt", Content: "c", Mode: 0o444},
		testutil.ZipEntry{Name: "link", Content: "target-bytes", Mode: fs.ModeSymlink | 0o777},
	))
	out := t.TempDir()
	require.NoError(t, unpack.Dir(in, out))

	stat := func(name string) fs.FileMode {
		info, err := os.Lstat(filepath.Join(out, name))
		require.NoError(t, err)
		return info.Mode()
	}
	assert.NotZero(t, stat("run.sh")&0o100, "execute permission is preserved")
	assert.Zero(t, stat("suid")&(fs.ModeSetuid|fs.ModeSetgid), "setuid/setgid bits are dropped")
	assert.NotZero(t, stat("ro")&0o200, "directories stay writable by the owner so that children can be extracted")
	assert.FileExists(t, filepath.Join(out, "ro", "child.txt"))
	assert.True(t, stat("link").IsRegular(), "symlink entries are extracted as regular files")
}

// --- Verification ---

func TestOpen_MalformedDetectionXML(t *testing.T) {
	pkg := makePackage(t, sample...)
	tests := map[string]struct {
		edit func(string) string
		want string
	}{
		"missing EncryptionInfo": {func(string) string {
			return "<ApplicationInfo><UnencryptedContentSize>10</UnencryptedContentSize></ApplicationInfo>"
		}, "no EncryptionInfo"},
		"not xml": {func(string) string { return "garbage" }, "failed to parse"},
		"short key": {func(s string) string {
			return replaceElement(s, "MacKey", base64.StdEncoding.EncodeToString(make([]byte, 8)))
		}, "MacKey must be 32 bytes"},
		"bad base64": {func(s string) string { return replaceElement(s, "InitializationVector", "@@@") }, "failed to decode InitializationVector"},
		"size mismatch": {func(s string) string {
			return replaceElement(s, "UnencryptedContentSize", "1")
		}, "implies"},
		"too large": {func(s string) string { return s + strings.Repeat(" ", metadata.MaxSize) }, "larger than"},
		"huge size": {func(s string) string {
			return replaceElement(s, "UnencryptedContentSize", "9223372036854775807")
		}, "invalid UnencryptedContentSize"},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			data := editDetection(t, pkg, tt.edit)
			assert.NotPanics(t, func() {
				_, err := unpack.Open(bytes.NewReader(data), int64(len(data)))
				assert.ErrorContains(t, err, tt.want)
			})
		})
	}
}

// Detection.xml variants that other tools may write: a BOM, an XML declaration, CRLF
// line endings, another ToolVersion and, for MSI setups, an MsiInfo element.
func TestOpen_AcceptsIntuneWinAppUtilStyleDetectionXML(t *testing.T) {
	pkg := makePackage(t, sample...)
	data := editDetection(t, pkg, func(s string) string {
		s = strings.Replace(s, `ToolVersion="1.8.7.0"`, `ToolVersion="1.8.6.0"`, 1)
		s = strings.Replace(s, "</EncryptionInfo>", "</EncryptionInfo>\n  <MsiInfo>\n    <MsiProductCode>{0}</MsiProductCode>\n  </MsiInfo>", 1)
		s = strings.ReplaceAll(s, "\n", "\r\n")
		return "\ufeff<?xml version=\"1.0\" encoding=\"utf-8\"?>\r\n" + s
	})
	p, err := unpack.Open(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	assert.Equal(t, "1.8.6.0", p.Info().ToolVersion)
	require.NoError(t, p.Decrypt(&bytes.Buffer{}))
}

func TestOpen_PackageStructureErrors(t *testing.T) {
	missing := testutil.MakeZip(t, testutil.ZipEntry{Name: metadata.ContentPath, Content: "x"})
	_, err := unpack.Open(bytes.NewReader(missing), int64(len(missing)))
	assert.ErrorContains(t, err, "Detection.xml not found")

	missing = testutil.MakeZip(t, testutil.ZipEntry{Name: metadata.DetectionPath, Content: "x"})
	_, err = unpack.Open(bytes.NewReader(missing), int64(len(missing)))
	assert.ErrorContains(t, err, "IntunePackage.intunewin not found")

	dup := testutil.MakeZip(t,
		testutil.ZipEntry{Name: metadata.DetectionPath, Content: "x"},
		testutil.ZipEntry{Name: metadata.DetectionPath, Content: "y"},
		testutil.ZipEntry{Name: metadata.ContentPath, Content: "z"},
	)
	_, err = unpack.Open(bytes.NewReader(dup), int64(len(dup)))
	assert.ErrorContains(t, err, "more than once")
}

func TestDecrypt_VerifiesIntegrity(t *testing.T) {
	pkg := makePackage(t, sample...)
	otherPkg := makePackage(t, sample...)
	otherInfo, err := metadata.Parse(testutil.ReadZipFile(t, testutil.ReadZip(t, otherPkg)[metadata.DetectionPath]))
	require.NoError(t, err)

	tests := map[string]struct {
		data []byte
		want string
	}{
		"tampered ciphertext": {editContent(t, pkg, func(b []byte) []byte { b[len(b)-1] ^= 1; return b }), "HMAC verification failed"},
		"tampered IV":         {editContent(t, pkg, func(b []byte) []byte { b[40] ^= 1; return b }), "HMAC verification failed"},
		"Mac differs from content": {editDetection(t, pkg, func(s string) string {
			return replaceElement(s, "Mac", base64.StdEncoding.EncodeToString(otherInfo.EncryptionInfo.Mac))
		}), "does not match Detection.xml"},
		"FileDigest differs from content": {editDetection(t, pkg, func(s string) string {
			return replaceElement(s, "FileDigest", base64.StdEncoding.EncodeToString(make([]byte, 32)))
		}), "digest of the decrypted content does not match"},
		"wrong encryption key": {editDetection(t, pkg, func(s string) string {
			return replaceElement(s, "EncryptionKey", base64.StdEncoding.EncodeToString(otherInfo.EncryptionInfo.EncryptionKey))
		}), ""}, // fails on padding or, rarely, on the digest check
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			p, err := unpack.Open(bytes.NewReader(tt.data), int64(len(tt.data)))
			require.NoError(t, err)
			err = p.Decrypt(&bytes.Buffer{})
			require.Error(t, err)
			if tt.want == "" {
				assert.Regexp(t, "padding|digest", err.Error())
				return
			}
			assert.ErrorContains(t, err, tt.want)
		})
	}
}

// A size that is off by less than a block passes the encrypted-size check in Open and
// must be caught after decryption.
func TestDecrypt_DetectsSmallSizeMismatch(t *testing.T) {
	pkg := makePackage(t, sample...)
	info, err := metadata.Parse(testutil.ReadZipFile(t, testutil.ReadZip(t, pkg)[metadata.DetectionPath]))
	require.NoError(t, err)
	n := info.UnencryptedContentSize
	wrong := n - 1
	if wrong/16 != n/16 {
		wrong = n + 1
	}
	data := editDetection(t, pkg, func(s string) string {
		return replaceElement(s, "UnencryptedContentSize", strconv.FormatInt(wrong, 10))
	})
	p, err := unpack.Open(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err, "same number of blocks, so Open cannot tell")
	assert.ErrorContains(t, p.Decrypt(&bytes.Buffer{}), "decrypted content is")
}

func TestDecrypt_WritesNothingWhenHMACFails(t *testing.T) {
	data := editContent(t, makePackage(t, sample...), func(b []byte) []byte { b[len(b)-1] ^= 1; return b })
	p, err := unpack.Open(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	var out bytes.Buffer
	require.Error(t, p.Decrypt(&out))
	assert.Zero(t, out.Len())
}

func TestDir_TamperedPackageExtractsNothing(t *testing.T) {
	data := editContent(t, makePackage(t, sample...), func(b []byte) []byte { b[len(b)-1] ^= 1; return b })
	out := filepath.Join(t.TempDir(), "out")
	require.Error(t, unpack.Dir(writePackage(t, data), out))
	assert.NoDirExists(t, out)
}
