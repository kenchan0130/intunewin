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
intunewin pack <source-folder> <output-file.intunewin>
```

Example:
```bash
intunewin pack ./myapp ./dist/myapp.intunewin
```

#### Unpack a file

```bash
intunewin unpack <input-file.intunewin> <output-folder>
```

Example:
```bash
intunewin unpack myapp.intunewin ./extracted
```

#### Help

```bash
intunewin --help
intunewin pack --help
intunewin unpack --help
```

### API

You can use the intunewin package in your Go applications with a simple stream-based API:

```go
package main

import (
    "archive/zip"
    "bytes"
    "fmt"
    "io"
    "os"
    "github.com/kenchan0130/intunewin/pkg/intunewin"
)

func main() {
    // Pack: Create a zip archive first
    zipBuf := new(bytes.Buffer)
    zipWriter := zip.NewWriter(zipBuf)
    
    // Add files to zip
    w1, _ := zipWriter.Create("app.exe")
    w1.Write([]byte("executable content"))
    
    w2, _ := zipWriter.Create("config/settings.json")
    w2.Write([]byte(`{"version": "1.0"}`))
    
    zipWriter.Close()
    
    // Pack the zip into intunewin format
    packedReader, err := intunewin.PackReader(bytes.NewReader(zipBuf.Bytes()))
    if err != nil {
        fmt.Printf("Pack failed: %v\n", err)
        return
    }
    
    // Write to file
    packedData, _ := io.ReadAll(packedReader)
    os.WriteFile("myapp.intunewin", packedData, 0644)
    
    // Unpack: Extract zip from intunewin format
    input, _ := os.ReadFile("myapp.intunewin")
    
    unpackedZipReader, err := intunewin.UnpackReader(bytes.NewReader(input))
    if err != nil {
        fmt.Printf("Unpack failed: %v\n", err)
        return
    }
    
    // Read the zip data
    unpackedZipData, _ := io.ReadAll(unpackedZipReader)
    
    // Parse and extract files from zip
    zipReader, _ := zip.NewReader(bytes.NewReader(unpackedZipData), int64(len(unpackedZipData)))
    for _, file := range zipReader.File {
        fmt.Printf("File: %s\n", file.Name)
        rc, _ := file.Open()
        content, _ := io.ReadAll(rc)
        fmt.Printf("Content: %s\n", content)
        rc.Close()
    }
}
```

#### API Functions

- `PackReader(zipReader io.Reader) (io.Reader, error)` - Takes a zip stream, returns encrypted intunewin package stream
- `UnpackReader(input io.Reader) (io.Reader, error)` - Takes an intunewin stream, returns decrypted zip stream

The API is designed for maximum flexibility:
- Works with any zip data (created by `archive/zip` or other tools)
- No file system dependencies in the low-level API
- Caller controls how files are organized and structured
- Streaming interface for efficient memory usage

## File Format

The `.intunewin` file is a ZIP archive containing:

1. `Metadata/Detection.xml`: Contains encryption keys, file sizes, and hash information
2. `Contents/IntunePackage.intunewin`: The encrypted and compressed source folder

## Development

### Running Tests

```bash
go test ./...
```

### Running Tests with Coverage

```bash
go test -cover ./...
```

### Building

```bash
go build -o intunewin cmd/intunewin/main.go
```

### Cross-compilation

Build for different platforms:

```bash
# Windows
GOOS=windows GOARCH=amd64 go build -o intunewin.exe cmd/intunewin/main.go

# macOS
GOOS=darwin GOARCH=amd64 go build -o intunewin-macos cmd/intunewin/main.go

# Linux
GOOS=linux GOARCH=amd64 go build -o intunewin-linux cmd/intunewin/main.go
```

## Reference Implementation

This implementation is inspired by [simeoncloud/IntuneAppBuilder](https://github.com/simeoncloud/IntuneAppBuilder).

## License

Apache License 2.0

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.