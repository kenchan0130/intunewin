// Package pack creates .intunewin packages.
package pack

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/kenchan0130/intunewin/internal/crypto"
	"github.com/kenchan0130/intunewin/internal/metadata"
)

// Options configures the Detection.xml written into a package.
type Options struct {
	// Name is written to the <Name> element. Defaults to the base name of SetupFile.
	Name string
	// SetupFile is the path of the setup file relative to the package content root.
	// Only its file name is written to the <SetupFile> element.
	SetupFile string
}

// DirOptions configures Dir.
type DirOptions struct {
	Options
	// Exclude lists glob patterns (path.Match syntax) of files and directories to leave out.
	// A pattern matches when it matches either the slash-separated path relative to the
	// source folder or the base name. A pattern ending in a slash matches directories only.
	Exclude []string
	// Overwrite allows replacing an existing output file.
	Overwrite bool
}

// Write builds an .intunewin package from content, a zip archive of the files to
// package, and writes it to dst. Content is streamed; memory use does not depend on
// the content size. A temporary file of roughly the content size is created in os.TempDir.
func Write(dst io.Writer, content io.Reader, opts Options) error {
	if opts.SetupFile == "" {
		return errors.New("setup file is required")
	}
	return write(dst, "", opts, func(w io.Writer) error {
		if _, err := io.Copy(w, content); err != nil {
			return fmt.Errorf("failed to read content: %w", err)
		}
		return nil
	})
}

// Dir packages the contents of sourceDir into the .intunewin file outputFile.
//
// If opts.SetupFile is empty, the first .msi file, or else the first .exe file, at the
// top level of sourceDir is used. The output is written atomically.
func Dir(sourceDir, outputFile string, opts DirOptions) error {
	info, err := os.Stat(sourceDir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("source folder does not exist: %s", sourceDir)
		}
		return fmt.Errorf("failed to access source folder: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("source path is not a directory: %s", sourceDir)
	}
	for _, p := range opts.Exclude {
		if _, err := path.Match(strings.TrimSuffix(p, "/"), ""); err != nil {
			return fmt.Errorf("invalid exclude pattern %q: %w", p, err)
		}
	}
	if !opts.Overwrite {
		if _, err := os.Lstat(outputFile); err == nil {
			return fmt.Errorf("output file already exists: %s (use --force to overwrite)", outputFile)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("failed to access output file: %w", err)
		}
	}

	root, err := os.OpenRoot(sourceDir)
	if err != nil {
		return fmt.Errorf("failed to open source folder: %w", err)
	}
	defer root.Close()

	skip := outputPathInSource(sourceDir, outputFile)
	setupFile, err := resolveSetupFile(root, opts.SetupFile, opts.Exclude, skip)
	if err != nil {
		return err
	}
	opts.SetupFile = setupFile

	entries, err := collect(root, opts.Exclude, skip)
	if err != nil {
		return err
	}
	if !containsFile(entries, setupFile) {
		return fmt.Errorf("setup file %s is excluded from the package", setupFile)
	}

	outputDir := filepath.Dir(outputFile)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return fmt.Errorf("failed to create output directory: %w", err)
	}
	tmp, err := createOutputTemp(outputDir, filepath.Base(outputFile))
	if err != nil {
		return fmt.Errorf("failed to create output file: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tmp.Close()
			_ = os.Remove(tmp.Name())
		}
	}()

	if err := write(tmp, outputDir, opts.Options, func(w io.Writer) error { return writeZip(w, root, entries) }); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	if err := os.Rename(tmp.Name(), outputFile); err != nil {
		return fmt.Errorf("failed to write output file: %w", err)
	}
	committed = true
	return nil
}

// createOutputTemp creates a uniquely named file in dir. Unlike os.CreateTemp, the file
// is created with mode 0666 before umask, so the final output gets the same permissions
// as a file created with os.Create.
func createOutputTemp(dir, base string) (*os.File, error) {
	for range 100 {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, fmt.Errorf("failed to generate temporary name: %w", err)
		}
		name := filepath.Join(dir, "."+base+"."+hex.EncodeToString(suffix[:])+".tmp")
		f, err := os.OpenFile(name, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o666)
		if errors.Is(err, fs.ErrExist) {
			continue
		}
		return f, err //nolint:wrapcheck // wrapped by the caller
	}
	return nil, errors.New("failed to find an unused temporary file name")
}

func write(dst io.Writer, tempDir string, opts Options, writeContent func(io.Writer) error) error {
	// Like the reference implementation, only the file name is recorded, even when the
	// setup file is in a subfolder.
	setupFile := path.Base(filepath.ToSlash(opts.SetupFile))
	name := opts.Name
	if name == "" {
		name = path.Base(setupFile)
	}

	keys, err := crypto.GenerateKeys()
	if err != nil {
		return fmt.Errorf("failed to generate encryption keys: %w", err)
	}

	tmp, err := os.CreateTemp(tempDir, ".intunewin-*.enc")
	if err != nil {
		return fmt.Errorf("failed to create temporary file: %w", err)
	}
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
	}()

	enc, err := crypto.NewEncryptor(tmp, keys)
	if err != nil {
		return fmt.Errorf("failed to initialize encryption: %w", err)
	}
	digest := sha256.New()
	var size countWriter
	if err := writeContent(io.MultiWriter(enc, digest, &size)); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return fmt.Errorf("failed to encrypt content: %w", err)
	}

	detection, err := metadata.Marshal(&metadata.Info{
		ToolVersion:            metadata.ToolVersion,
		Name:                   name,
		UnencryptedContentSize: size.n,
		FileName:               metadata.ContentFileName,
		SetupFile:              setupFile,
		EncryptionInfo: metadata.EncryptionInfo{
			EncryptionKey:        keys.EncryptionKey,
			MacKey:               keys.MacKey,
			InitializationVector: keys.InitializationVector,
			Mac:                  enc.Mac(),
			ProfileIdentifier:    metadata.ProfileIdentifier,
			FileDigest:           digest.Sum(nil),
			FileDigestAlgorithm:  metadata.FileDigestAlgorithm,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create Detection.xml: %w", err)
	}
	if _, err := tmp.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("failed to rewind temporary file: %w", err)
	}

	// The outer zip entries are stored uncompressed, as IntuneWinAppUtil does.
	zw := zip.NewWriter(dst)
	now := time.Now()
	if err := addStored(zw, metadata.DetectionPath, bytes.NewReader(detection), now); err != nil {
		return err
	}
	if err := addStored(zw, metadata.ContentPath, tmp, now); err != nil {
		return err
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to finish package: %w", err)
	}
	return nil
}

func addStored(zw *zip.Writer, name string, r io.Reader, modified time.Time) error {
	w, err := zw.CreateHeader(&zip.FileHeader{Name: name, Method: zip.Store, Modified: modified})
	if err != nil {
		return fmt.Errorf("failed to create %s: %w", name, err)
	}
	if _, err := io.Copy(w, r); err != nil {
		return fmt.Errorf("failed to write %s: %w", name, err)
	}
	return nil
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) {
	c.n += int64(len(p))
	return len(p), nil
}

// resolveSetupFile validates the given setup file, or picks one when spec is empty.
// The result is a slash-separated path relative to root, spelled as in the file system.
// When picking, files that are excluded or that are the output file (skip) are passed over.
func resolveSetupFile(root *os.Root, spec string, exclude []string, skip string) (string, error) {
	if spec != "" {
		p := filepath.Clean(spec)
		if !filepath.IsLocal(p) {
			return "", fmt.Errorf("setup file must be a relative path inside the source folder: %s", spec)
		}
		info, err := root.Stat(p)
		if err != nil {
			return "", fmt.Errorf("setup file not found in source folder: %s: %w", spec, err)
		}
		if !info.Mode().IsRegular() {
			return "", fmt.Errorf("setup file is not a regular file: %s", spec)
		}
		return actualName(root, filepath.ToSlash(p)), nil
	}

	dirEntries, err := fs.ReadDir(root.FS(), ".")
	if err != nil {
		return "", fmt.Errorf("failed to read source folder: %w", err)
	}
	for _, ext := range []string{".msi", ".exe"} {
		for _, e := range dirEntries {
			if !strings.EqualFold(path.Ext(e.Name()), ext) || e.Name() == skip || excluded(e.Name(), false, exclude) {
				continue
			}
			if info, err := root.Stat(e.Name()); err == nil && info.Mode().IsRegular() {
				return e.Name(), nil
			}
		}
	}
	return "", errors.New("no .msi or .exe file found at the top level of the source folder; specify the setup file explicitly")
}

// actualName returns name, an existing slash-separated path relative to root, with each
// element spelled as listed in its directory. On case-insensitive file systems the user
// may spell the setup file differently from the entries collected from the directory.
func actualName(root *os.Root, name string) string {
	fsys := root.FS()
	dir := "."
	for elem := range strings.SplitSeq(name, "/") {
		entries, err := fs.ReadDir(fsys, dir)
		if err != nil {
			return name
		}
		match := ""
		for _, e := range entries {
			if e.Name() == elem {
				match = elem
				break
			}
			if match == "" && strings.EqualFold(e.Name(), elem) {
				match = e.Name()
			}
		}
		if match == "" {
			return name
		}
		dir = path.Join(dir, match)
	}
	return dir
}

// outputPathInSource returns the slash-separated path of outputFile relative to
// sourceDir if it lies inside it, or "" otherwise.
func outputPathInSource(sourceDir, outputFile string) string {
	src, err := filepath.EvalSymlinks(sourceDir)
	if err != nil {
		return ""
	}
	src, err = filepath.Abs(src)
	if err != nil {
		return ""
	}
	outDir := filepath.Dir(outputFile)
	if resolved, err := filepath.EvalSymlinks(outDir); err == nil {
		outDir = resolved
	}
	out, err := filepath.Abs(filepath.Join(outDir, filepath.Base(outputFile)))
	if err != nil {
		return ""
	}
	rel, err := filepath.Rel(src, out)
	if err != nil || !filepath.IsLocal(rel) {
		return ""
	}
	return filepath.ToSlash(rel)
}

type entry struct {
	name     string // slash-separated, relative to the source root
	dir      bool
	perm     fs.FileMode
	modified time.Time
}

func containsFile(entries []entry, name string) bool {
	for _, e := range entries {
		if !e.dir && e.name == name {
			return true
		}
	}
	return false
}

func excluded(name string, isDir bool, patterns []string) bool {
	base := path.Base(name)
	for _, p := range patterns {
		if dirOnly := strings.HasSuffix(p, "/"); dirOnly {
			if !isDir {
				continue
			}
			p = strings.TrimSuffix(p, "/")
		}
		if ok, _ := path.Match(p, name); ok {
			return true
		}
		if ok, _ := path.Match(p, base); ok {
			return true
		}
	}
	return false
}

// collect lists the entries to package. Symbolic links to files inside the source
// folder are stored as regular files; anything else that is not a regular file or
// directory is rejected.
func collect(root *os.Root, exclude []string, skip string) ([]entry, error) {
	fsys := root.FS()
	var entries []entry
	files := 0
	err := fs.WalkDir(fsys, ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name == "." {
			return nil
		}
		if name == skip || excluded(name, d.IsDir(), exclude) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}

		isLink := d.Type()&fs.ModeSymlink != 0
		info, err := fs.Stat(fsys, name)
		if err != nil {
			if isLink {
				return fmt.Errorf("symbolic link %s is broken or points outside the source folder: %w", name, err)
			}
			return fmt.Errorf("failed to stat %s: %w", name, err)
		}
		switch {
		case info.IsDir():
			if isLink {
				return fmt.Errorf("symbolic links to directories are not supported: %s", name)
			}
			entries = append(entries, entry{name: name, dir: true, perm: info.Mode().Perm(), modified: info.ModTime()})
		case info.Mode().IsRegular():
			files++
			entries = append(entries, entry{name: name, perm: info.Mode().Perm(), modified: info.ModTime()})
		default:
			return fmt.Errorf("unsupported file type %s: %s", info.Mode().Type(), name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to walk source folder: %w", err)
	}
	if files == 0 {
		return nil, errors.New("source folder contains no files")
	}
	return pruneSkipParents(entries, skip), nil
}

// pruneSkipParents drops the directories leading to skip that are left empty because
// skip was left out, so that writing the output into the source folder does not add
// an empty directory to the package.
func pruneSkipParents(entries []entry, skip string) []entry {
	for dir := path.Dir(skip); skip != "" && dir != "."; dir = path.Dir(dir) {
		empty := true
		for _, e := range entries {
			if strings.HasPrefix(e.name, dir+"/") {
				empty = false
				break
			}
		}
		if !empty {
			break
		}
		entries = slices.DeleteFunc(entries, func(e entry) bool { return e.dir && e.name == dir })
	}
	return entries
}

func writeZip(w io.Writer, root *os.Root, entries []entry) error {
	zw := zip.NewWriter(w)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Modified: e.modified}
		if e.dir {
			h.Name += "/"
			h.SetMode(fs.ModeDir | e.perm)
			if _, err := zw.CreateHeader(h); err != nil {
				return fmt.Errorf("failed to add directory %s: %w", e.name, err)
			}
			continue
		}
		h.Method = zip.Deflate
		h.SetMode(e.perm)
		fw, err := zw.CreateHeader(h)
		if err != nil {
			return fmt.Errorf("failed to add file %s: %w", e.name, err)
		}
		if err := copyFile(fw, root, e.name); err != nil {
			return err
		}
	}
	if err := zw.Close(); err != nil {
		return fmt.Errorf("failed to finish content archive: %w", err)
	}
	return nil
}

func copyFile(w io.Writer, root *os.Root, name string) error {
	f, err := root.Open(filepath.FromSlash(name))
	if err != nil {
		return fmt.Errorf("failed to open %s: %w", name, err)
	}
	defer f.Close()
	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("failed to read %s: %w", name, err)
	}
	return nil
}
