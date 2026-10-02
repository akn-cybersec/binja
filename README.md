# binja - ELF Binary Analysis and Patching Tool

```
██████╗ ██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██║████╗  ██║     ██║██╔══██╗
██████╔╝██║██╔██╗ ██║     ██║███████║
██╔══██╗██║██║╚██╗██║██   ██║██╔══██║
██████╔╝██║██║ ╚████║╚█████╔╝██║  ██║
╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝
   ELF Binary Analysis & Patching Tool
```

binja is a focused command-line tool for static analysis and patching of ELF binaries. It provides manual ELF parsing, Capstone-powered disassembly, cross-reference scanning, ROP gadget discovery, and patching utilities via an interactive REPL or single-command invocation.

---

## Table of Contents

- Quick Start
- Features
- Installation and Build
- Usage
- Command Reference
- Examples and Workflows
- Architecture and Internals
- Project Structure
- Versioning
- Upgrading
- Limitations
- Troubleshooting
- Comparison to Other Tools
- Contributing
- Security Notice
- Author
- License

---

## Quick Start

```bash
# Clone and build (no root needed to build)
git clone https://github.com/akn-cybersec/binja
cd binja
make

# Optional: install system-wide so 'binja' works from anywhere
chmod +x install.sh
./install.sh

# Run
binja ./target_binary            # if installed
./binja ./target_binary          # from the build directory

# One-shot commands
./binja ./target_binary info
./binja ./target_binary disas main
./binja ./target_binary strings 6
```

Common workflow example:

```
binja> info
binja> functions
binja> disas vuln_func
binja> xrefs 0x401234
binja> patch 0x401200 9090
binja> rop find --ret
```

---

## Features

| Feature | Description |
|---|---|
| ELF parsing | Manual header, section, segment, and symbol table parsing (no libelf dependency) |
| Disassembly | x86 / x86-64 disassembly using the Capstone framework |
| Cross-reference scanning | Scans `.text` for `call`, `jmp`, `mov`, and other branch instructions whose operand text matches a target address |
| Binary patching | In-memory and on-disk patching with automatic `.bak` backup creation |
| Protection analysis | Detects NX, PIE, stack canary (symbol-based), and RELRO (none/full) |
| String extraction | Extracts printable strings from `.rodata` and `.data` |
| Interactive REPL | Persistent command history stored in `.binja_history` |
| ROP gadget finder | Scans executable sections for gadgets (e.g. `ret`, `syscall`) with filtering options and Python exploit export |
| Hexdump | Hex and ASCII dump of any section with optional offset and length |
| Section/segment listing | Lists ELF sections and program headers with flags and permissions |
| Version info | `binja --version` reports the release version, git commit, and build timestamp |

---

## Installation and Build

### Dependencies

- Linux x86-64
- GCC or Clang with C++17 support
- Capstone disassembly framework
- GNU Make

### Install Capstone

**Arch Linux:**
```bash
sudo pacman -S capstone
```

**Ubuntu / Debian:**
```bash
sudo apt-get install libcapstone-dev
```

**From source:**
```bash
git clone https://github.com/capstone-engine/capstone
cd capstone && ./make.sh && sudo make install
```

### Build binja

```bash
# Optimized release build (no root required)
make

# Debug build
make debug

# Install using the bundled installer script
chmod +x install.sh
./install.sh

# Clean build artifacts
make clean

# List available Makefile targets
make help
```

Note: `make debug` sets `-g -O0 -DDEBUG` in addition to the release flags. To enable sanitizers, add `-fsanitize=address,undefined` to `DEBUG_FLAGS` in the Makefile.

The resulting binary is `./binja` in the project directory. You can run it directly from there, or use `./install.sh` to make the installer executable and run the project install script, which copies it to `/usr/bin`.

If you have previously installed binja to a different prefix, remove the old binary first to avoid one copy silently shadowing the other on your `PATH`:

```bash
which -a binja
sudo rm /path/to/old/binja
```

---

## Usage

binja supports two operating modes: interactive REPL and single-command (non-interactive) mode.

### Interactive Mode

Start the REPL by supplying a target binary:

```bash
./binja ./target_binary
```

The REPL records commands to `.binja_history` in the current working directory. The in-session `history` command displays the recent session commands by index; timestamps are stored in the on-disk history file.

Signal handling: `Ctrl+C` does not exit the REPL; use `exit`, `quit`, `Ctrl+D`, or an empty line to leave.

### Command-Line Mode

Run a single command non-interactively for scripting and automation:

```bash
./binja ./binary info
./binja ./binary functions
./binja ./binary disas main
./binja ./binary strings 6
```

Note: `hexdump`, `sections`, and `segments` are currently available only in interactive mode.

---

## Command Reference

This project includes commands such as `info`, `functions`, `disas`, `xrefs`, `patch`, `strings`, `hexdump`, `sections`, `segments`, `rop`, and `version`. See the in-REPL `help` for full usage and examples.

Key commands:

- `info`: Display ELF metadata (entry point, architecture, endianness, sections, protections).
- `functions`: List function symbols with addresses and sizes.
- `disas <name|address>`: Disassemble a named function or an address (targets `.text`).
- `xrefs <address>`: Textual operand match search in `.text` for references to the given address (hex).
- `patch <address> <hex_bytes>`: Overwrite bytes at a virtual address; creates a `.bak` backup before the first write.
- `strings [min_len]`: Extract printable strings from `.rodata` and `.data` (default minimum length: 4).
- `rop find [--ret] [--syscall]`: Search executable sections for ROP gadgets matching the given filters.
- `version`: Print the current version and build info (same as `binja --version`).

Warning: patches are written to disk immediately. The `.bak` file is created before the first write and should be kept until the patched binary has been validated.

---

## Examples and Workflows

1. Reconnaissance and analysis:

```bash
./binja ./challenge
binja> info
binja> sections
binja> segments
binja> functions
binja> strings 5
binja> rop find --ret
```

2. Identify a vulnerable function and trace callers:

```
binja> functions
binja> disas vuln
binja> xrefs 0x4011a4
```

---

## Architecture and Internals

binja consists of five primary modules: `main` (CLI and REPL), `elf_parser` (manual ELF parsing), `disassembler` (Capstone wrapper and xref scanning), `patcher` (file writes and backups), and `rop_finder` (gadget scanning, filtering, and chain/export helpers). ELF structures are read directly from the memory-mapped file; disassembly uses the Capstone C API. Patching performs virtual-to-file offset translation by walking `PT_LOAD` segments and writes bytes via standard stream I/O.

---

## Project Structure

```
binja/
├── main.cpp
├── elf_parser.cpp
├── elf_parser.h
├── disassembler.cpp
├── disassembler.h
├── patcher.cpp
├── patcher.h
├── rop_finder.cpp
├── rop_finder.h
├── VERSION
├── Makefile
└── README.md
```

---

## Versioning

The project follows a simple `MAJOR.MINOR` scheme recorded in the `VERSION` file at the repository root, bumped manually with each release. The Makefile stamps this version, along with the current git commit hash and UTC build timestamp, directly into the compiled binary.

Check the current version:

```bash
binja --version
# or
binja -v
```

Example output:

```
binja 1.1 (4df5d3a-2026-08-13T10:12:00Z)
```

To release a new version, update `VERSION` and commit it alongside your other changes:

```bash
echo "1.1" > VERSION
git add VERSION
git commit -m "Bump version to 2.1"
```

---

## Upgrading

After pulling changes, always rebuild from a clean state before reinstalling, and confirm the running binary matches what you expect:

```bash
make clean
make
chmod +x install.sh
./install.sh
binja --version
```

If `binja --version` does not show the expected version or commit hash, check for a stale binary earlier in your `PATH`:

```bash
which -a binja
```

If more than one path is listed, the first one is what actually runs. Remove or update the outdated copy so only the current install remains.

---

## Limitations

- ELF only: no PE (Windows) or Mach-O (macOS) support
- x86 / x86-64 only: section logic is implemented for these architectures
- Limited 32-bit testing
- RELRO detection: reports `none` or `full` (no partial-RELRO distinction)
- Stack canary detection is symbol-based and may false-negative on stripped binaries
- `xrefs` is a textual operand match rather than a relocation-aware analysis
- `disas` targets `.text` only
- Some dynamic-section helpers are stubs and not exposed via CLI
- No DWARF parsing or dynamic (runtime) analysis

---

## Troubleshooting

Common issues and remedies:

- `Cannot resolve address 0x...`: Verify the address with `segments`; ensure the address falls within a `PT_LOAD` segment and that PIE/ASLR considerations are addressed.
- Missing Capstone: run `ldd ./binja` and ensure `libcapstone.so` resolves, or install `libcapstone-dev`.
- Permission denied when patching: ensure the target file is writable (`chmod u+w ./target`).
- `.binja_history` not updating: run binja from a writable directory.
- Colors or version info look wrong after an update: run `which -a binja` to check for a stale binary shadowing the current one, then see Upgrading above.

---

## Comparison to Other Tools

binja is a lightweight CLI utility intended for quick static analysis and patching workflows (for example, CTFs or exploit development). It is not a replacement for full-featured reverse engineering platforms such as Ghidra, Binary Ninja, or radare2.

---

## Contributing

Contributions are welcome. Before submitting a PR, run `make` and `make debug`, test against representative ELF binaries, and keep changes focused and consistent with the existing C++17 code style.

Planned or suitable first issues include partial-RELRO detection, GOT/PLT table support, exposing interactive-only commands for non-interactive mode, expanding 32-bit coverage, and adding JSON output.

---

## Security Notice

Do not use binja to analyze or modify binaries without authorization. The tool is intended for security research, CTFs, and authorized reverse engineering work. The authors are not responsible for misuse.

---

## Author

> "Trust The Process" - My Princess

> kaizen_dragon

---

## License

MIT License

```
Copyright (c) 2026 kaizen_dragon

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
```