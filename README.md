# binja — Binary Analysis Tool for ELF Files

```
██████╗ ██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██║████╗  ██║     ██║██╔══██╗
██████╔╝██║██╔██╗ ██║     ██║███████║
██╔══██╗██║██║╚██╗██║██   ██║██╔══██║
██████╔╝██║██║ ╚████║╚█████╔╝██║  ██║
╚═════╝ ╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝
   ELF Binary Analysis & Patching Tool
```


A lightweight, no-frills ELF analysis tool built for reverse engineers, binary exploit developers, and CTF players. No bloat, no GUI, no libelf dependency — just raw ELF parsing, Capstone-powered disassembly, and a clean interactive REPL.

---

## Table of Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation & Build](#installation--build)
- [Usage](#usage)
  - [Interactive Mode](#interactive-mode)
  - [Command-Line Mode](#command-line-mode)
  - [Command Reference](#command-reference)
- [Examples & Workflows](#examples--workflows)
- [Architecture & Internals](#architecture--internals)
- [Project Structure](#project-structure)
- [Limitations](#limitations)
- [Troubleshooting](#troubleshooting)
- [Comparison to Other Tools](#comparison-to-other-tools)
- [Contributing](#contributing)
- [Security Notice](#security-notice)
- [License](#license)

---

## Quick Start

```bash
# Build
git clone https://github.com/akn-cybersec/binja
cd binja && make

# Drop into interactive REPL
./binja ./target_binary

# One-shot command
./binja ./target_binary info
./binja ./target_binary disas main
./binja ./target_binary strings 6
```

Common workflow for a CTF binary:

```
binja> info
binja> functions
binja> disas vuln_func
binja> xrefs 0x401234
binja> patch 0x401200 9090
```

---

## Features

| Feature | Description |
|---|---|
| 🔍 **ELF Parsing** | Manual header, section, segment, and symbol table parsing — zero libelf dependency |
| 📝 **Disassembly** | x86/x86-64 disassembly via Capstone engine |
| 🔗 **Cross-Reference Finding** | Scans all executable sections for calls/jumps to a target address |
| 💾 **Binary Patching** | In-memory and on-disk patching with automatic `.bak` backup creation |
| 📊 **Protection Analysis** | Detects NX, PIE, Stack Canary, and RELRO |
| 📜 **String Extraction** | Pulls printable strings from `.rodata` and `.data` |
| 🎮 **Interactive REPL** | Persistent command history with timestamps, saved to `.binja_history` |
| 🔲 **Hexdump** | Hex + ASCII dump of any section, with optional offset and length |
| 📋 **Section/Segment Listing** | All ELF sections and program headers with flags and permissions |

---

## Installation & Build

### Dependencies

- Linux x86-64
- GCC or Clang with C++17 support
- [Capstone](http://www.capstone-engine.org/) disassembly framework
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
# Optimized release build
make

# Debug build (with -g, ASAN, verbose output)
make debug

# Clean build artifacts
make clean
```

The resulting binary is `./binja`. No install step required — run it from the project directory or copy it somewhere on your `$PATH`.

---

## Usage

binja has two operating modes: **interactive** and **command-line**.

### Interactive Mode

Launch with a binary path to enter the REPL:

```bash
./binja ./target_binary
```

```
[*] Loading: ./target_binary
[*] ELF64 detected — x86-64
[*] Loaded 27 sections, 9 segments
[*] Symbol table: 42 functions resolved

binja> _
```

The REPL persists command history to `.binja_history` (with timestamps) across sessions.

**History expansion:**

| Shorthand | Action |
|---|---|
| `!!` | Repeat the last command |
| `!5` | Repeat command #5 from history |
| `history` | Show full history with timestamps |

**Signal handling:**  
`Ctrl+C` clears the current line and shows a fresh prompt — it does **not** exit. Use `exit` or `quit` to leave.

---

### Command-Line Mode

Run a single command non-interactively — useful for scripting and piping output:

```bash
./binja ./binary info
./binja ./binary functions
./binja ./binary disas main
./binja ./binary strings 6
./binja ./binary xrefs 0x401234
./binja ./binary hexdump .rodata 0 64
```

---

### Command Reference

#### `info`
Display ELF metadata: entry point, architecture, class, endianness, section count, and detected binary protections.

```
binja> info

  File:        ./vuln
  Format:      ELF64 (Little Endian)
  Entry Point: 0x401080
  Sections:    27
  Segments:    9

  [Protections]
  NX:           Enabled
  PIE:          Disabled
  Stack Canary: Disabled
  RELRO:        Partial
```

---

#### `functions`
List all function symbols with their virtual addresses and sizes.

```
binja> functions

  [Functions — 12 resolved]
  0x401080   _start               (48 bytes)
  0x4010b0   __libc_csu_init      (101 bytes)
  0x401156   main                 (78 bytes)
  0x4011a4   vuln                 (63 bytes)
  0x4011e3   win                  (31 bytes)
```

> **Note:** If the binary is stripped, `functions` will show an empty list. Use `disas 0x<address>` to disassemble by address directly.

---

#### `strings [min_len]`
Extract printable strings from `.rodata` and `.data`. Default minimum length is 4.

```
binja> strings 6

  [Strings — .rodata]
  0x402004   "Enter your name: "
  0x402016   "Hello, %s!\n"
  0x402022   "cat /flag"
  0x40202c   "/bin/sh"
```

---

#### `disas <function_name|address>`
Disassemble a function by name or by hex address.

```
binja> disas vuln

  [Disassembly — vuln @ 0x4011a4]
  0x4011a4:  push   rbp
  0x4011a5:  mov    rbp, rsp
  0x4011a8:  sub    rsp, 0x40
  0x4011ac:  lea    rax, [rbp-0x40]
  0x4011b0:  mov    rsi, rax
  0x4011b3:  lea    rdi, [rip+0x84e]
  0x4011ba:  mov    eax, 0x0
  0x4011bf:  call   0x401060 <scanf@plt>
  0x4011c4:  nop
  0x4011c5:  leave
  0x4011c6:  ret
```

```bash
# By address
./binja ./binary disas 0x4011a4
```

---

#### `xrefs <address>`
Scan all executable sections for instructions that call or jump to the target address. Useful for identifying every caller of a function.

```
binja> xrefs 0x4011e3

  [Cross-References to 0x4011e3]
  0x401200:  call   0x4011e3    (in section .text)
  0x40123a:  jmp    0x4011e3    (in section .text)

  2 reference(s) found.
```

---

#### `patch <address> <hex_bytes>`
Patch the binary in memory and on disk at the given address with the provided hex byte string. A `.bak` backup of the original file is created automatically before the first write.

```
binja> patch 0x4011bf 9090

  [*] Backup created: ./vuln.bak
  [*] Patching 0x4011bf — wrote 2 byte(s)
  [+] Done. Verify with: disas vuln
```

```bash
# NOP out a call instruction (5 bytes)
binja> patch 0x4011bf 9090909090

# Overwrite a jump condition
binja> patch 0x401200 eb0e
```

> ⚠️ Patches are written to disk. The `.bak` file is your safety net — keep it until you are sure the patch is correct.

---

#### `hexdump <section> [offset] [length]`
Dump section data in hex + ASCII format. Offset and length are optional.

```
binja> hexdump .rodata 0 64

  [Hexdump — .rodata  offset=0  length=64]
  00000000  45 6e 74 65 72 20 79 6f  75 72 20 6e 61 6d 65 3a  |Enter your name:|
  00000010  20 00 48 65 6c 6c 6f 2c  20 25 73 21 0a 00 63 61  | .Hello, %s!..ca|
  00000020  74 20 2f 66 6c 61 67 00  2f 62 69 6e 2f 73 68 00  |t /flag./bin/sh.|
  00000030  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
```

---

#### `sections`
List all ELF sections with addresses, sizes, and flags.

```
binja> sections

  [Sections — 27 total]
  Idx  Name              Address            Size     Flags
  ---  ----              -------            ----     -----
    1  .text             0x0000000000401080 0x01a3   AX
    2  .rodata           0x0000000000402000 0x0060   A
    3  .data             0x0000000000404000 0x0010   WA
    4  .bss              0x0000000000404010 0x0008   WA
    5  .symtab           0x0000000000000000 0x0240   
    6  .strtab           0x0000000000000000 0x00e1   
  ...
```

---

#### `segments`
List program headers (PT_LOAD, PT_GNU_STACK, etc.) with virtual addresses, sizes, and permissions.

```
binja> segments

  [Segments — 9 total]
  Type            VirtAddr           FileSiz    MemSiz     Flags
  ----            --------           -------    ------     -----
  PT_LOAD         0x0000000000400000 0x000002e8 0x000002e8 R
  PT_LOAD         0x0000000000401000 0x000001a3 0x000001a3 R E
  PT_LOAD         0x0000000000402000 0x000000c4 0x000000c4 R
  PT_LOAD         0x0000000000403e00 0x0000022c 0x0000023c R W
  PT_GNU_STACK    0x0000000000000000 0x00000000 0x00000000 R W
```

---

#### `history`
Show the full command history with timestamps.

```
binja> history

  [Command History]
  1  [2025-11-14 02:11:33]  info
  2  [2025-11-14 02:11:40]  functions
  3  [2025-11-14 02:11:48]  disas vuln
  4  [2025-11-14 02:12:01]  xrefs 0x4011e3
  5  [2025-11-14 02:12:15]  patch 0x4011bf 9090909090
```

---

#### `help`
Display command reference and usage hints in the REPL.

#### `exit` / `quit`
Exit interactive mode cleanly.

---

## Examples & Workflows

### 1. Full binary recon

```bash
./binja ./challenge

binja> info         # Entry point, protections
binja> sections     # Identify interesting sections
binja> segments     # Check NX (PT_GNU_STACK flags)
binja> functions    # What's in the symbol table?
binja> strings 5    # Any juicy strings? /bin/sh? flag paths?
```

---

### 2. Identifying a vulnerable function and its callers

```bash
binja> functions
# spot 'vuln' at 0x4011a4

binja> disas vuln
# see the scanf with a fixed buffer — classic overflow

binja> xrefs 0x4011a4
# find who calls vuln, trace execution path
```

---

### 3. Patching out a security check

```bash
binja> disas check_auth
# 0x401320:  test   eax, eax
# 0x401322:  jne    0x401380   <-- jump if auth fails

# Patch jne (75 XX) to jmp (eb XX) to always take the branch
binja> patch 0x401322 eb5c

binja> disas check_auth
# verify the patch landed correctly
```

---

### 4. Locating a win function for a ret2win

```bash
binja> functions
# 0x4011e3   win   (31 bytes)

binja> disas win
# confirm it calls system("/bin/sh") or similar

binja> xrefs 0x4011e3
# verify it's never called legitimately — pure overflow target
```

---

### 5. Extracting hidden strings from a crackme

```bash
binja> strings 8
# look for long strings — flags, passwords, keys

binja> hexdump .rodata
# when you need the raw bytes around a string
```

---

### 6. Using history expansion

```bash
binja> disas main
binja> disas vuln
binja> !!         # re-runs: disas vuln
binja> !1         # re-runs: disas main
binja> history    # review full session
```

---

## Architecture & Internals

binja is built around four cooperating modules:

```
┌─────────────────────────────────────────────────────┐
│                      main.cpp                       │
│         CLI dispatch / Interactive REPL             │
│         Command history / Signal handling           │
└────────────┬──────────────────────┬────────────────┘
             │                      │
    ┌────────▼────────┐    ┌────────▼────────┐
    │  elf_parser.cpp │    │ disassembler.cpp │
    │                 │    │                  │
    │  ELF64/32 hdr   │    │  Capstone init   │
    │  Section table  │    │  x86/x86-64 dis  │
    │  Program hdrs   │    │  xref scanner    │
    │  .symtab        │    └─────────────────┘
    │  .dynsym        │
    │  .strtab        │    ┌─────────────────┐
    │  String extract │    │   patcher.cpp   │
    │  Protection det.│    │                 │
    └─────────────────┘    │  .bak creation  │
                           │  In-memory patch│
                           │  On-disk write  │
                           └─────────────────┘
```

**ELF parsing** is done entirely by hand — `Elf64_Ehdr`, `Elf64_Shdr`, `Elf64_Phdr`, `Elf64_Sym` structs are read directly from the mapped file. No libelf, no BFD, no external parsing library.

**Disassembly** wraps the Capstone C API in a thin C++ class. `cs_open`, `cs_disasm`, and `cs_close` handle the lifecycle; the xref scanner iterates over all `SHF_EXECINSTR` sections and checks each decoded instruction's operands against the target address.

**Patching** uses `mmap`/`fseek`+`fwrite` to overwrite bytes at the file offset corresponding to a given virtual address, computed by walking the PT_LOAD segments to find the correct `p_offset` + `(vaddr - p_vaddr)` translation.

---

## Project Structure

```
binja/
├── main.cpp            # CLI entry point, REPL, command dispatch, history
├── elf_parser.cpp      # Manual ELF parsing: headers, sections, symbols, strings, protections
├── disassembler.cpp    # Capstone wrapper: disassembly engine, xref scanning
├── patcher.cpp         # Binary patching with .bak backup creation
├── elf_parser.h        # ELFParser class definition
├── disassembler.h      # Disassembler class definition
├── patcher.h           # Patcher class definition
├── Makefile            # Build system: release / debug / clean targets
└── README.md
```

---

## Limitations

- **ELF only** — no PE (Windows) or Mach-O (macOS) support
- **x86 / x86-64** — Capstone supports other archs but binja's section logic is currently wired for these two; other architectures will fail gracefully
- **Limited 32-bit testing** — 32-bit ELF parsing is implemented but less battle-tested than 64-bit
- **No DWARF parsing** — debug info (file/line mapping) is not read; stripped binaries show addresses only
- **No ROP gadget search** — planned for a future release
- **No dynamic analysis** — static analysis only; no tracing, no emulation

---

## Troubleshooting

| Error | Cause | Fix |
|---|---|---|
| `Cannot resolve address 0x...` | Address falls outside all PT_LOAD segments | Verify the address with `segments`; make sure the binary is not PIE with ASLR active |
| `Function not found: foo` | Binary is stripped, no `.symtab` | Use `disas 0x<address>` directly |
| `Capstone init failed` | Missing or incorrect Capstone install | Run `ldd ./binja` and check `libcapstone.so` resolves |
| `Permission denied` when patching | File is read-only | `chmod u+w ./target` before patching |
| History not saved | `.binja_history` not writable in CWD | Run binja from a directory you own |

---

## Comparison to Other Tools

binja is not a replacement for radare2, Ghidra, or Binary Ninja (the commercial product). It is a **focused, lightweight CLI tool** for the specific workflows that come up most in binary exploitation and CTF work.

| Capability | binja | readelf | objdump | radare2 |
|---|:---:|:---:|:---:|:---:|
| ELF section/segment listing | ✅ | ✅ | ✅ | ✅ |
| Disassembly | ✅ | ❌ | ✅ | ✅ |
| Symbol table listing | ✅ | ✅ | ✅ | ✅ |
| Cross-reference finder | ✅ | ❌ | ❌ | ✅ |
| Binary patching (with backup) | ✅ | ❌ | ❌ | ✅ |
| Protection analysis | ✅ | Partial | ❌ | ✅ |
| Interactive REPL w/ history | ✅ | ❌ | ❌ | ✅ |
| String extraction | ✅ | ❌ | ✅ | ✅ |
| Scripting / API | ❌ | ❌ | ❌ | ✅ |
| Dependency count | 1 (capstone) | 0 | 0 | Many |
| Binary size | ~100KB | ~50KB | ~200KB | >10MB |

**Use binja when:** you want fast answers in a CTF, you are writing exploit scripts and want quick one-liners, or you just don't want to wait for radare2 to load.

**Use radare2/Ghidra/Binary Ninja when:** you need decompilation, advanced scripting, graph views, or analysis of non-ELF formats.

---

## Tips for Reverse Engineering Workflows

```
1. Start with `info` — know your protections before anything else.
   PIE + Full RELRO + Canary changes everything about your exploit path.

2. `strings` before `disas` — a /bin/sh or a flag path tells you
   immediately what the intended vector is.

3. Use `xrefs` to trace data flow backward — find every site that
   calls into a vulnerable function before you assume it's unreachable.

4. Keep patches surgical — NOP the minimum number of bytes,
   verify with `disas` after every patch.

5. .bak files are sacred — never delete them until the patched
   binary is confirmed working.
```

---

## Contributing

Bug reports, feature requests, and pull requests are welcome.

**Before submitting a PR:**
- Run `make` and `make debug` cleanly
- Test against at least one real ELF binary (statically linked and dynamically linked)
- Keep additions self-contained within the relevant source file
- Match the existing code style (C++17, no STL containers in the hot path if avoidable)

**Planned / good-first-issue features:**
- ROP gadget finder
- GOT/PLT table display
- 32-bit ELF test suite
- DWARF line info parsing (basic)
- JSON output mode for scripting integration

---

## Security Notice

binja is a **static analysis and patching tool** intended for:

- Security research on software you own or have explicit written permission to analyze
- CTF challenges
- Reverse engineering for interoperability and vulnerability research under applicable law

Do not use binja to analyze or patch binaries without authorization. The authors are not responsible for misuse.

---

## Author
> **"Trust The Process" — My Princess**

**kaizen_dragon**

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
