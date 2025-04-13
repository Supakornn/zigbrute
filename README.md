# ZigBrute

A high-performance password cracking tool written in Zig, designed for security research and educational purposes.

## Features

- Advanced password detection and analysis
- Multiple bruteforce algorithms
- Configurable attack modes
- High-performance implementation using Zig
- Cross-platform support

## Requirements

- Zig 0.12.0 or later
- A C compiler (for building dependencies)

## Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/zigbrute.git
cd zigbrute
```

2. Build the project:

```bash
zig build
```

The executable will be available in `zig-out/bin/`.

## Usage

Basic usage:

```bash
zigbrute [options] <input>
```

### Options

- `-h, --help`: Show help message
- `-a, --advanced`: Enable advanced mode
- `-o, --output <path>`: Save results to specified path

## Project Structure

- `src/`: Source code directory
  - `main.zig`: Main entry point and CLI interface
  - `bruteforce.zig`: Bruteforce implementation
  - `detector.zig`: Password detection logic
  - `algorithms.zig`: Various attack algorithms
  - `utils/`: Utility functions and helpers

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Disclaimer

This tool is intended for educational and research purposes only. Use responsibly and only on systems you own or have explicit permission to test.
