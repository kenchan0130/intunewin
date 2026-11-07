package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kenchan0130/intunewin/internal/testutil"
	"github.com/kenchan0130/intunewin/pkg/intunewin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func runCLI(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

func newSource(t *testing.T) string {
	t.Helper()
	src := filepath.Join(t.TempDir(), "app")
	testutil.WriteFiles(t, src, map[string]string{"setup.exe": "exe", "install.cmd": "cmd", "debug.log": "log", "sub/a.txt": "a"})
	return src
}

func readInfo(t *testing.T, file string) *intunewin.Info {
	t.Helper()
	data, err := os.ReadFile(file)
	require.NoError(t, err)
	info, err := intunewin.ReadInfo(bytes.NewReader(data), int64(len(data)))
	require.NoError(t, err)
	return info
}

func TestVersion(t *testing.T) {
	code, stdout, _ := runCLI(t, "--version")
	assert.Equal(t, 0, code)
	assert.Contains(t, stdout, "dev (commit none, built unknown)")
}

func TestErrorIsPrintedOnceWithoutUsage(t *testing.T) {
	code, stdout, stderr := runCLI(t, "unpack", filepath.Join(t.TempDir(), "missing.intunewin"), t.TempDir())
	assert.Equal(t, 1, code)
	assert.Empty(t, stdout)
	assert.Equal(t, 1, strings.Count(stderr, "Error:"), stderr)
	assert.Contains(t, stderr, "does not exist")
	assert.NotContains(t, stderr, "Usage:")
}

func TestArgumentErrorIsPrintedOnce(t *testing.T) {
	code, _, stderr := runCLI(t, "pack", "only-one-arg")
	assert.Equal(t, 1, code)
	assert.Equal(t, 1, strings.Count(stderr, "Error:"), stderr)
	assert.Contains(t, stderr, "accepts 2 arg(s)")
}

func TestProgressGoesToStderrAndQuietSuppressesIt(t *testing.T) {
	src := newSource(t)
	out := filepath.Join(t.TempDir(), "o.intunewin")

	code, stdout, stderr := runCLI(t, "pack", src, out)
	require.Equal(t, 0, code, stderr)
	assert.Empty(t, stdout, "stdout stays clean for scripting")
	assert.Contains(t, stderr, "Successfully created")

	code, stdout, stderr = runCLI(t, "-q", "unpack", out, filepath.Join(t.TempDir(), "x"))
	require.Equal(t, 0, code, stderr)
	assert.Empty(t, stdout)
	assert.Empty(t, stderr)
}

func TestPackFlags(t *testing.T) {
	src := newSource(t)
	out := filepath.Join(t.TempDir(), "o.intunewin")

	code, _, stderr := runCLI(t, "pack", src, out, "--setup-file", "install.cmd", "--name", "My App", "--exclude", "*.log")
	require.Equal(t, 0, code, stderr)
	info := readInfo(t, out)
	assert.Equal(t, "install.cmd", info.SetupFile)
	assert.Equal(t, "My App", info.Name)

	extracted := filepath.Join(t.TempDir(), "x")
	require.NoError(t, intunewin.UnpackDir(out, extracted))
	assert.NoFileExists(t, filepath.Join(extracted, "debug.log"))
	assert.FileExists(t, filepath.Join(extracted, "sub", "a.txt"))
}

func TestPackDefaultsSetupFileToDetectedInstaller(t *testing.T) {
	src := newSource(t)
	out := filepath.Join(t.TempDir(), "o.intunewin")
	code, _, stderr := runCLI(t, "-q", "pack", src, out)
	require.Equal(t, 0, code, stderr)
	assert.Equal(t, "setup.exe", readInfo(t, out).SetupFile)
}

func TestPackRequiresForceToOverwrite(t *testing.T) {
	src := newSource(t)
	out := filepath.Join(t.TempDir(), "o.intunewin")
	require.NoError(t, os.WriteFile(out, []byte("existing"), 0o600))

	code, _, stderr := runCLI(t, "-q", "pack", src, out)
	assert.Equal(t, 1, code)
	assert.Contains(t, stderr, "already exists")

	code, _, stderr = runCLI(t, "-q", "pack", src, out, "--force")
	assert.Equal(t, 0, code, stderr)
}

func TestUnpackToCurrentDirectory(t *testing.T) {
	src := newSource(t)
	pkg := filepath.Join(t.TempDir(), "o.intunewin")
	code, _, stderr := runCLI(t, "-q", "pack", src, pkg)
	require.Equal(t, 0, code, stderr)

	dir := t.TempDir()
	t.Chdir(dir)
	code, _, stderr = runCLI(t, "-q", "unpack", pkg, ".")
	require.Equal(t, 0, code, stderr)
	assert.FileExists(t, filepath.Join(dir, "sub", "a.txt"))
}
