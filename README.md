# pwnelf

ELF x86-64 static analysis for CTF exploitation. Mitigation checks, disassembly,
ROP gadget search, pattern offsets.

## Overview

pwnelf is a command-line tool for reading ELF x86-64 binaries during CTF exploitation
work. It reports which mitigations a binary was built with, disassembles functions,
finds ROP gadgets, locates strings, and computes buffer offsets from crash values.

It maps the file and reads it. It never runs the binary under analysis, makes no
network calls, and writes nothing outside stdout and stderr. Instruction decoding is
delegated to Zydis; everything else is written from scratch.

This is a learning project under active development. Read the Status section before
assuming a command exists.

## Contents

- [Status](#status)
- [Build](#build)
- [Quick start](#quick-start)
- [Usage](#usage)
- [Exit codes](#exit-codes)
- [Supported platforms](#supported-platforms)
- [Development](#development)

## Status

| Command  | Status      | Purpose                                                  |
|----------|-------------|----------------------------------------------------------|
| `cyclic` | implemented | de Bruijn pattern generation and offset lookup           |
| `info`   | planned     | header summary, NX / PIE / RELRO / canary / FORTIFY      |
| `disasm` | planned     | function-level disassembly with symbol and PLT names     |
| `gadget` | planned     | ROP, JOP and syscall gadgets by reverse scan             |
| `search` | planned     | strings and byte patterns with virtual addresses         |

## Build

No release binaries yet. Build from source with CMake 3.20+ and a C++17 compiler.
CLI11 and GoogleTest are fetched at configure time, so the first configure needs
network access.

```bash
cmake -S . -B build
cmake --build build
```

The binary lands at `build/pwnelf`.

## Quick start

```bash
pwnelf cyclic 200                      # de Bruijn pattern
pwnelf cyclic --lookup laaa            # offset of a faulting value
pwnelf cyclic --lookup 0x6161616c      # same, as read from a register
pwnelf cyclic --help                   # per-command help
```

## Usage

### Patterns

Every 4-byte window of the generated pattern is unique, so one crash gives the exact
offset.

```bash
pwnelf cyclic 32
# aaaabaaacaaadaaaeaaafaaagaaahaaa

pwnelf cyclic --lookup baaa
# 4

pwnelf cyclic --lookup 0x61616162
# 4
```

Integer arguments are read little-endian, matching the byte order you see in a
register or a memory dump. Width comes from the digit count: 8 hex digits is a 4-byte
value, 16 is an 8-byte value. Leading zeroes count, so `0x00616161` is a 4-byte value
containing a NUL, not a 3-byte one.

Maximum pattern length is 26⁴ = 456976 bytes. Longer requests are rejected rather than
truncated.

## Exit codes

| Code | Meaning                                                        |
|------|----------------------------------------------------------------|
| `0`  | success, result on stdout                                      |
| `1`  | well-formed input, no result (value absent from the pattern)   |
| `2`  | malformed input                                                |

Results go to stdout, diagnostics to stderr, and the two never mix. A failed lookup
writes nothing to stdout.

## Supported platforms

| OS    | Arch   | Status                                    |
|-------|--------|-------------------------------------------|
| macOS | arm64  | development host, builds and runs         |
| Linux | x86_64 | expected to build, not yet verified       |

Reading an x86-64 ELF does not require an x86-64 host. The tool parses the file rather
than running it.

## Development

```bash
cmake --build build && ctest --test-dir build --output-on-failure
```

A separate build directory turns on UndefinedBehaviorSanitizer and libc++ hardening,
which adds bounds checks to standard containers.

```bash
cmake -S . -B build-san -DCMAKE_BUILD_TYPE=Debug -DPWNELF_SANITIZE=ON
cmake --build build-san && ctest --test-dir build-san --output-on-failure
```

AddressSanitizer is absent by design. Its runtime hangs on the macOS build used here,
so ASan coverage is deferred to Linux.

```
include/pwnelf/   public headers
src/              library sources and CLI entry point
tests/            GoogleTest unit tests and CTest CLI tests
```

Analysis code lives in a static library, `pwnelf_core`. `src/main.cpp` only wires CLI11
options to it. Unit tests call the library directly; CTest cases run the built binary
and assert on stdout and exit code, because those are the contract any calling script
depends on.

