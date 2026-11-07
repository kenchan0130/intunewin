# intunewin

A cross-platform CLI tool for creating and extracting Microsoft Intune `.intunewin` files.

## Features

- 📦 **Pack**: Package folders into encrypted `.intunewin` files
- 🔓 **Unpack**: Extract `.intunewin` files back to folders
- 🌍 **Cross-platform**: Works on Windows, macOS, and Linux
- 📝 **Simple API**: Easy-to-use public API for programmatic access

## Installation

### Download from Releases (Recommended)

Download the latest binary for your platform from the [Releases](https://github.com/kenchan0130/intunewin/releases) page.

### Using go install

```bash
go install github.com/kenchan0130/intunewin/cmd/intunewin@latest
```

Make sure your `$GOPATH/bin` or `$GOBIN` is in your `$PATH`.

### Build from Source

```bash
git clone https://github.com/kenchan0130/intunewin.git
cd intunewin
make build
# Or manually:
# go build -o bin/intunewin cmd/intunewin/main.go
```

## Usage

### CLI

#### Pack a folder

```bash
intunewin pack <source-folder> <output-file.intunewin> [flags]
```

| Flag | Description |
| --- | --- |
| `-s`, `--setup-file` | Setup file, relative to the source folder. Defaults to the first `.msi`, or else `.exe`, file at the top level of the source folder. Only the file name is written to `Detection.xml`. |
| `-n`, `--name` | Application name written to `Detection.xml`. Defaults to the setup file name. |
| `-e`, `--exclude` | Glob pattern of files or directories to exclude, matched against the relative path and the base name. Repeatable. |
| `-f`, `--force` | Overwrite the output file if it already exists. |
| `-q`, `--quiet` | Suppress progress messages (printed to stderr). |

Examples:

```bash
intunewin pack ./myapp ./dist/myapp.intunewin
intunewin pack ./myapp ./dist/myapp.intunewin --setup-file install.cmd --exclude .DS_Store --exclude '*.log'
```

Notes:

- Symbolic links to files inside the source folder are stored as regular files. Links that point outside the source folder, and links to directories, are rejected.
- If the output file is inside the source folder, it is not included in the package.
- The output file is written atomically; a failed run never leaves a partial file.
- Temporary files about as large as the content are created next to the output (not in the system temp directory).

#### Unpack a file

```bash
intunewin unpack <input-file.intunewin> <output-folder>
```

The package is verified (HMAC, file digest and size from `Detection.xml`) before anything is extracted. Extraction is confined to the output folder.

#### Help / version

```bash
intunewin --help
intunewin --version
```

### API

The `pkg/intunewin` package exposes a streaming API. Memory use does not depend on the package size. Because the format requires seeking, temporary files about as large as the content are used: next to the output for `PackDir`/`UnpackDir`, and in the system temp directory (`TMPDIR`) for `Pack`.

```go
package main

import (
    "log"
    "os"

    "github.com/kenchan0130/intunewin/pkg/intunewin"
)

func main() {
    // Folder to file
    if err := intunewin.PackDir("./myapp", "myapp.intunewin", intunewin.PackDirOptions{
        Options: intunewin.PackOptions{SetupFile: "setup.exe"},
        Exclude: []string{".DS_Store"},
    }); err != nil {
        log.Fatal(err)
    }

    // Read Detection.xml (including the values needed for a Microsoft Graph upload)
    f, err := os.Open("myapp.intunewin")
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()
    st, _ := f.Stat()
    info, err := intunewin.ReadInfo(f, st.Size())
    if err != nil {
        log.Fatal(err)
    }
    log.Printf("name=%s setup=%s size=%d", info.Name, info.SetupFile, info.UnencryptedContentSize)

    // File to folder
    if err := intunewin.UnpackDir("myapp.intunewin", "./extracted"); err != nil {
        log.Fatal(err)
    }
}
```

#### API Functions

- `PackDir(sourceDir, outputFile string, opts PackDirOptions) error` - Packages a folder into a file.
- `UnpackDir(inputFile, outputDir string) error` - Verifies and extracts a package into a folder.
- `Pack(dst io.Writer, content io.Reader, opts PackOptions) error` - Packages a zip archive stream. `opts.SetupFile` is required.
- `Unpack(dst io.Writer, src io.ReaderAt, size int64) (*Info, error)` - Verifies a package and writes its content (a zip archive) to `dst`. If it returns an error, discard what was written.
- `ReadInfo(src io.ReaderAt, size int64) (*Info, error)` - Reads `Detection.xml` without decrypting.
- `PackReader` / `UnpackReader` - Deprecated in-memory variants kept for compatibility.

## File Format

The `.intunewin` file is a ZIP archive (entries stored uncompressed) containing:

1. `IntuneWinPackage/Metadata/Detection.xml`: Application name, setup file, unencrypted content size, and the encryption information (keys, IV, HMAC, SHA256 file digest)
2. `IntuneWinPackage/Contents/IntunePackage.intunewin`: A ZIP archive of the source folder, encrypted as `[HMAC-SHA256 (32 bytes)][IV (16 bytes)][AES-256-CBC ciphertext]`, where the HMAC covers the IV and ciphertext

## Development

### Running Tests

```bash
make test
```

### Running Tests with Coverage

```bash
go test -cover ./...
```

### Building

```bash
make build
```

## Reference Implementation

This implementation is inspired by [simeoncloud/IntuneAppBuilder](https://github.com/simeoncloud/IntuneAppBuilder).

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.