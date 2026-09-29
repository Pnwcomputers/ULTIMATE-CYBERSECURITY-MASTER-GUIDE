# 🔍 Ghidra Master Guide

Last reviewed: 2026-09-29

> [!CAUTION]
> **Authorized use only.** The techniques below are for authorized security testing,
> education, and defensive research. Using them against systems you do not own or
> lack explicit written permission to test is illegal. See
> [LEGAL.md](../LEGAL.md).

**Prerequisites:** Comfort with a command line, basic C, and how programs load into
memory. Isolated lab recommended: see [Homelab](../Homelab/).

## 🎯 Purpose

A standalone operational guide to [Ghidra](https://github.com/NationalSecurityAgency/ghidra/),
the NSA's open-source software reverse engineering (SRE) suite. It is organized into
five parts so you can move from first principles to production workflows:

1. Why binaries look the way they do, and how Ghidra fits the tool landscape
2. Daily analysis in the CodeBrowser
3. Customization, collaboration, scripting, and automation
4. How loaders, processors, the decompiler, and compilers actually work
5. Obfuscation, patching, and binary comparison at scale

This is original documentation synthesized from official Ghidra sources and public
SRE practice. It is not a reproduction of any commercial book.

> [!NOTE]
> Version note. Public release as of August 2026 is **Ghidra 12.1.x** and requires a
> **64-bit JDK 21**. Development (`master`) documentation already describes **Ghidra 12.2**
> and **JDK 25**. Always match your JDK to the *Getting Started* file inside *your*
> extracted zip, not to a blog post.

---

## Table of contents

- [Part I: Getting Started](#part-i-getting-started)
  - [Chapter 1: Introduction to Disassembly](#chapter-1-introduction-to-disassembly)
  - [Chapter 2: Reversing and Disassembly Tools](#chapter-2-reversing-and-disassembly-tools)
  - [Chapter 3: Meet Ghidra](#chapter-3-meet-ghidra)
- [Part II: Basic Ghidra Usage](#part-ii-basic-ghidra-usage)
  - [Chapter 4: Beginning Your Analysis](#chapter-4-beginning-your-analysis)
  - [Chapter 5: Exploring Ghidra's Data Displays](#chapter-5-exploring-ghidras-data-displays)
  - [Chapter 6: Making Sense of a Disassembly](#chapter-6-making-sense-of-a-disassembly)
  - [Chapter 7: Refining a Disassembly](#chapter-7-refining-a-disassembly)
  - [Chapter 8: Working with Data Types and Data Structures](#chapter-8-working-with-data-types-and-data-structures)
  - [Chapter 9: Understanding Cross-References](#chapter-9-understanding-cross-references)
  - [Chapter 10: Using Graph Views](#chapter-10-using-graph-views)
- [Part III: Customizing and Extending Ghidra](#part-iii-customizing-and-extending-ghidra)
  - [Chapter 11: Using Ghidra Collaboratively](#chapter-11-using-ghidra-collaboratively)
  - [Chapter 12: Customizing Ghidra](#chapter-12-customizing-ghidra)
  - [Chapter 13: Extending Ghidra's Worldview](#chapter-13-extending-ghidras-worldview)
  - [Chapter 14: Basic Scripting with Ghidra and PyGhidra](#chapter-14-basic-scripting-with-ghidra-and-pyghidra)
  - [Chapter 15: Integrated Scripting with Eclipse and GhidraDev](#chapter-15-integrated-scripting-with-eclipse-and-ghidradev)
  - [Chapter 16: Running Ghidra in Headless Mode](#chapter-16-running-ghidra-in-headless-mode)
- [Part IV: A Deeper Dive](#part-iv-a-deeper-dive)
  - [Chapter 17: Loaders](#chapter-17-loaders)
  - [Chapter 18: Processors](#chapter-18-processors)
  - [Chapter 19: The Decompiler](#chapter-19-the-decompiler)
  - [Chapter 20: Compiler Variations](#chapter-20-compiler-variations)
- [Part V: Real-World Applications](#part-v-real-world-applications)
  - [Chapter 21: Obfuscation and Emulation](#chapter-21-obfuscation-and-emulation)
  - [Chapter 22: Patching Binaries](#chapter-22-patching-binaries)
  - [Chapter 23: BSim and Other Comparison Tools](#chapter-23-bsim-and-other-comparison-tools)
- [Appendix: Ghidra for IDA Users](#appendix-ghidra-for-ida-users)
- [Official sources](#official-sources)

---

# Part I: Getting Started

## Chapter 1: Introduction to Disassembly

### What a binary actually is

A compiler and linker turn source into a container: headers, sections or segments,
symbols (sometimes stripped), relocations, imports/exports, and raw bytes. The CPU
never sees "functions" or "variables." It sees bytes at addresses and an instruction
pointer.

Disassembly is the reconstruction of *possible* instructions from those bytes.
Decompilation is a later reconstruction of *possible* C-like control flow and data
flow. Both are hypotheses. Your job is to test them.

### Why analysts disassemble

Typical authorized reasons:

| Mission | Question the listing helps answer |
| --- | --- |
| Malware / incident response | What does this sample do, to whom, and how does it persist? |
| Vulnerability research | Where is attacker-controlled data used unsafely? |
| Interoperability | How does this closed protocol or file format actually work? |
| Compiler / toolchain validation | Did the compiler emit what the language rules promised? |
| Crash / debug analysis | What was executing at this RIP/PC? |

### Two classical algorithms

**Linear sweep** walks the file from a start offset, decoding the next instruction
after the previous one. Fast. Fragile when data sits between code, when the ISA is
variable-length (x86), or when junk bytes are inserted.

**Recursive descent** starts at known entry points (the program entry, exports,
reset vectors) and follows control-flow edges: fall-through, branches, calls.
It only disassembles bytes it can *prove* are reachable. Indirect jumps
(`jmp rax`, computed tables) require extra analysis.

Ghidra's default analyzer is a recursive-descent engine plus a large set of
follow-on analyzers (stack frames, calling conventions, switch tables, strings,
and more). Think of auto-analysis as "a strong first hypothesis," not a verdict.

### The unit of work

You will constantly move between four layers:

1. **Bytes** in a memory block
2. **Instructions** with operands
3. **Functions** with a start address, body, and calling convention
4. **Data types** that give those bytes meaning

If a listing looks wrong, ask which layer is lying.

### Checkpoint

- If two adjacent bytes can be a 2-byte instruction *or* the end of one instruction
  plus the start of another, which algorithm is more likely to pick the wrong split?
- Why does stripping symbols make disassembly harder *without* making it impossible?

---

## Chapter 2: Reversing and Disassembly Tools

Ghidra is not the whole lab. Use cheap, specialized tools first so you know what
you are importing.

### Classification (what is this file?)

```bash
file ./sample
xxd -l 256 ./sample
# Windows PE extras
# pecheck, pestudio, or Python pefile in a lab VM
# ELF extras
readelf -h ./sample
readelf -S ./sample
```

`file` uses magic bytes. It can be wrong on packed or truncated samples. Treat it
as a hint.

### Inventory (what is inside?)

```bash
strings -a -n 8 ./sample | less
# ELF
nm -C ./sample          # may fail if stripped
ldd ./sample            # dynamic deps; do this in a sandbox
objdump -d ./sample     # GNU linear-sweep disassembly
# macOS
otool -hv ./sample
otool -tV ./sample
# Windows (Developer Command Prompt)
dumpbin /headers sample.exe
dumpbin /exports sample.exe
```

`c++filt` (or `llvm-cxxfilt`) recovers readable names from Itanium/MSVC mangling
when symbols exist.

### Disassemblers and related suites

| Tool | Strength | Typical use |
| --- | --- | --- |
| Ghidra | Free, strong decompiler, multi-user server, scripting | Daily SRE |
| IDA / Hex-Rays | Mature UI, huge plugin history | Shops already licensed |
| Binary Ninja | Modern UI, BNIL, good API | Interactive analysis |
| radare2 / Cutter | CLI-first, scriptable | Automation, odd formats |
| Capstone / Keystone | Libraries, not full SRE suites | Custom tooling |
| objdump / llvm-objdump | Everywhere | Quick sanity check |

### A sane intake order

1. Hash and store the original (`sha256sum`). Never analyze the only copy.
2. Classify format and architecture.
3. Note packer / overlay / unusual section names.
4. Extract strings and imports. Many questions die here.
5. Only then open Ghidra.

### Checkpoint

- `objdump -d` and Ghidra disagree on where a function ends. Which one should you
  distrust first, and what evidence would settle it?
- Why is `ldd` on an untrusted ELF a lab-safety question, not just a convenience?

---

## Chapter 3: Meet Ghidra

### What you are installing

Ghidra is a Java application plus native components. There is no installer. You
extract a zip and launch a script.

Official source: [NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra).
Download the asset named `ghidra_<version>_PUBLIC_<date>.zip`. The two GitHub
"Source Code" archives are *not* the release.

### Requirements (verify against *your* zip)

From upstream `GhidraDocs/GettingStarted.md` and current public releases:

| Item | Typical public 12.1.x | Development 12.2 docs |
| --- | --- | --- |
| OS | Windows 10 1809+, Linux, macOS 10.13+ | Same; 32-bit OS deprecated |
| Java | 64-bit **JDK 21** | 64-bit **JDK 25** |
| RAM | 4 GB minimum | Same |
| Disk | ~1 GB for the install | Same |
| Python | 3.9–3.14 for PyGhidra; debugger similar | Same ranges documented |

JDK vendors called out upstream: Adoptium Temurin, Amazon Corretto. A JRE-only
install is not the documented requirement.

### Install

```bash
# Confirm Java *before* you launch
java -version

# Linux / macOS
unzip ghidra_*_PUBLIC_*.zip
cd ghidra_*_PUBLIC
./ghidraRun

# Windows
# Extract with Explorer or a current 7-Zip, then:
ghidraRun.bat
```

> [!WARNING]
> Do not extract a new version on top of an old one. Paths containing `!` (any OS)
> or `^` (Windows) prevent launch. On macOS, clear quarantine first:
> `xattr -d com.apple.quarantine ghidra_*.zip`

Backup projects before upgrading: copy the `.gpr` file *and* the sibling `.rep`
directory.

### Layout of an install

| Path | Role |
| --- | --- |
| `ghidraRun` / `ghidraRun.bat` | GUI launch |
| `support/pyghidraRun` | GUI with native CPython 3 |
| `support/analyzeHeadless` | Batch / CI analysis |
| `support/launch.properties` | JVM args, Java override |
| `support/ghidraDebug` | Foreground debug launch |
| `server/` | Shared-project server |
| `Ghidra/Features/` | Feature modules (BSim, Debugger, PyGhidra, …) |
| `GhidraDocs/` | Getting Started, GhidraClass, help extras |
| `Extensions/` | Optional / community extensions |

### First launch

1. Accept the license.
2. The **Project Window** opens. Ghidra is project-oriented: nothing is analyzed
   outside a project.
3. Create a **Non-Shared Project** for solo work. Shared projects need a Ghidra
   Server (Chapter 11).
4. Tool Chest icons launch tools. **CodeBrowser** is the daily analysis tool.
   **Debugger** is a separate default tool you can import via
   **Tools → Import Default Tools**.

### Support channels

- In-app Help (`Help → Contents`) — the primary reference
- [GitHub issues](https://github.com/NationalSecurityAgency/ghidra/issues)
- [ghidra-sre.org](https://ghidra-sre.org) (points at official releases)
- Built-in `GhidraDocs/GhidraClass` student material

### Checkpoint

- Why does Ghidra refuse to work without a project?
- If `ghidraRun` says it cannot find a supported JDK, which two places do you
  check before reinstalling Java?

---

# Part II: Basic Ghidra Usage

## Chapter 4: Beginning Your Analysis

### Create a project

**File → New Project** (or `Ctrl+N` / `Cmd+N`).

- **Non-Shared:** directory on disk. Fine for personal labs.
- **Shared:** talks to a Ghidra Server repository.

Pick a path with no `!` or `^`. Name the project after the engagement, not after
a single file — projects hold many programs.

### Import a file

**File → Import File**, drag-and-drop onto the project window, or `I`.

Ghidra guesses:

- Format (PE, ELF, Mach-O, raw, firmware blobs, …)
- Language / compiler spec (for example `x86:LE:64:default` + `gcc`)

Read the import summary. Wrong language is the most expensive early mistake.
For raw firmware you often must set base address and language by hand.

Options worth knowing:

- **Import with options** to load only some sections
- **Add to program** later for overlays
- Language search if auto-detect picks the 32-bit variant of a 64-bit file

### Open CodeBrowser and analyze

Double-click the program in the project tree. CodeBrowser asks whether to
analyze. First time on a format: **Yes**, then review the analyzer list.

Useful first-pass discipline:

- Leave default analyzers on for a normal user-mode PE/ELF.
- On huge or obfuscated binaries, run a *short* first pass (code discovery,
  strings, stack analysis) and enable expensive analyzers later.
- After analysis, **Window → Analysis Reports** if something looks missing.

Status bar shows busy analyzers. Do not rename aggressively until the first
full pass finishes.

### The first ten minutes

1. **Symbol Tree → Imports / Exports / Functions.** What does this program talk to?
2. **Defined Strings.** Error messages and URLs often name features.
3. Entry point and `main` (or `WinMain`, `DllMain`, `ServiceMain`).
4. Decompiler on `main`. Does the C look like a real program or like a stub
   that unpacks the rest?

### Checkpoint

- Auto-detect chose `x86:LE:32` but `file` said `ELF 64-bit`. What breaks if you
  proceed anyway?
- When would you refuse the default analyzer set?

---

## Chapter 5: Exploring Ghidra's Data Displays

CodeBrowser is a set of linked windows. Clicking an address in one moves the
others.

### Core windows

| Window | What it shows | Why you open it |
| --- | --- | --- |
| Listing | Address, bytes, instruction or data, comments | Ground truth |
| Decompiler | C-like reconstruction of the current function | Fast comprehension |
| Symbol Tree | Namespaces, imports, exports, functions, labels, classes | Orientation |
| Data Type Manager | Built-in, program, and archive types | Struct work |
| Bytes | Hex / ASCII of memory | Raw verification |
| Defined Strings | Recovered string data | Feature mapping |
| Function Call Graph / Function Graph | Who calls whom / basic blocks | Control flow |
| Comments / Bookmarks | Your notes | Persistence |
| Memory Map | Blocks, permissions, image base | Loader sanity |
| Register / Equates | Named constants | Decode flags |
| Script Manager | Java / Python scripts | Automation |

### Listing columns

A listing row is typically:

`address    bytes    mnemonic    operands    eol-comment`

You can add or hide fields with the Listing listing-field editor (right-click
the header). Useful extras: operand scalars as hex, function offsets, xref
counts.

### Decompiler pane

The decompiler is not a second listing. It is a *translation* that can be
wrong when types are wrong. Clicking a token jumps the listing. Middle-click
or hover often shows the underlying p-code / address.

If listing and decompiler disagree, believe the listing until you fix types
(Chapter 8) or control flow (Chapter 7).

### Docking

Drag window tabs. Save a working layout with **File → Save Tool**. Team
layouts can be exported as `.tool` files.

### Checkpoint

- You click a local variable in the decompiler and the listing jumps to a stack
  offset, not a mnemonic. What does that tell you about how Ghidra stores that
  variable?
- Which window answers "is this byte range even mapped?" before you invent a
  function there?

---

## Chapter 6: Making Sense of a Disassembly

### Functions first

Ghidra's function is the primary analysis object: body, stack frame, calling
convention, signature, and thunk flag.

Signs a function boundary is wrong:

- Decompiler output that never returns, or returns five times
- Stack offsets that grow without a prologue
- A "function" that contains an ASCII table
- Cross-references into the middle of the body that look like new entries

### Calling conventions

x86-64 System V (Linux/macOS): integer/pointer args in `RDI, RSI, RDX, RCX, R8, R9`,
return in `RAX`. Windows x64: `RCX, RDX, R8, R9` plus shadow space. 32-bit
`cdecl` / `stdcall` / `fastcall` differ on who cleans the stack.

If the decompiler shows `param_1` used as a `FILE*` but typed as `int`, the
convention or signature is incomplete — not the CPU.

### Comments are evidence

Ghidra comment types:

| Type | Typical use |
| --- | --- |
| EOL | Short note on one instruction |
| Pre / Post | Block explanation |
| Plate | Banner at function start |
| Repeatable | Appears at every xref to this address |

Write *why*, not *what*. "`cmp eax, 0x5a`" does not need a comment that says
"compare eax to 0x5A". "`0x5A == max retries from config blob at DAT_00xx`" does.

### Names

`L` (or right-click → Rename) on functions, labels, and data. Good names are
the highest-leverage edit you can make. Prefer `parse_tlv_header` over `FUN_00401230`.

Namespaces keep vendor / library code out of your analysis namespace.

### Reading a function without drowning

1. Signature and calling convention
2. Early returns and error paths
3. Loops and switch dispatch
4. Calls out (especially imports)
5. Writes to globals
6. Only then the clever middle

### Checkpoint

- A function has one incoming xref but five `RET` sites. Is that automatically
  five functions?
- When should you *not* rename an import?

---

## Chapter 7: Refining a Disassembly

Auto-analysis will be wrong. Fixing it is the job.

### Common repairs

| Symptom | Typical fix |
| --- | --- |
| Data decoded as code | Undefine (`U`), then define as bytes/string/struct |
| Code decoded as data | Select bytes → **Disassemble** (`D`) |
| Function too large | **Create Function** at inner entry; split |
| Function too small | **Edit Function** body, or undefine and recreate |
| Missed switch | Let Switch Analysis rerun, or add refs by hand |
| Wrong instruction length | Undefine the range, disassemble from the correct start |
| Delay slots / odd ISA | Check language ID before "fixing" bytes |

### Key actions

- `C` create function, `F` edit function signature
- `U` undefine, `D` disassemble, `I` make data / cycle data types
- `T` set data type
- `Y` set function return/variable type from decompiler or listing
- `X` jump to xrefs
- `G` go to address or symbol
- `;` add comment
- Bookmarks (`Ctrl+D` depending on key binding) for "come back here"

Re-run selected analyzers from **Analysis → Auto Analyze** rather than
re-importing.

### Function signatures

**Edit Function** sets name, calling convention, varargs, inline/noreturn,
custom storage. Noreturn matters: if `exit` is not marked noreturn, every
caller looks like it keeps executing into garbage.

### When to stop polishing

Stop when additional edits no longer change a decision you have to make
(IOC, vulnerability class, capability). Perfect listings are not a deliverable.
Correct enough listings are.

### Checkpoint

- You press `D` in the middle of an x86 instruction and the next twenty
  instructions become nonsense. What invariant did you break?
- Why does marking `abort` as noreturn improve functions that never call
  `abort` directly?

---

## Chapter 8: Working with Data Types and Data Structures

Types are how Ghidra turns bytes into meaning. The decompiler is a type
consumer. Garbage types in, garbage C out.

### Where types live

**Data Type Manager** archives:

- Built-in types (`int`, `undefined4`, pointers)
- Program types (local to this binary)
- File archives (`.gdt`) you share with a team
- Parsed C headers (`File → Parse C Source`)

Commit reusable structs to an archive, not only to one program.

### Apply types

- Listing: `T` on a data address
- Decompiler: `T` or `Y` on a variable
- **Apply data type** to a memory range
- Create arrays (`[` in many bindings) when you see counted repetition

### Structures

Right-click in Data Type Manager → **New → Structure**. Add fields, set
offsets explicitly when the compiler inserted padding. Use **Unpack** /
component editors when a field is itself a struct.

For PE/ELF, apply well-known structs (`IMAGE_NT_HEADERS`, `Elf64_Ehdr`)
only in regions that *are* those headers. Do not paint file headers onto
heap snapshots.

### Pointers and typedefs

`typedef` a `DWORD` that is really an `NTSTATUS`. Create a pointer type
`FOO *` rather than leaving `undefined8` so xrefs and the decompiler
propagate the pointed-to struct.

### Function definitions as types

Function-definition types belong on function pointers in vtables and
callback tables. That is how a listing of addresses becomes a table of
named operations.

### Checkpoint

- The decompiler shows `*(param_1 + 0x18)`. What single type edit often
  turns that into `param_1->length`?
- Why can parsing a vendor header into the *wrong* architecture archive
  silently poison later programs?

---

## Chapter 9: Understanding Cross-References

A cross-reference (xref) is Ghidra's record that address A uses address B.

### Kinds you will see

| Kind | Meaning |
| --- | --- |
| Read / Write | Data access |
| Call | Direct call to a function |
| Jump | Direct branch |
| Pointer | Address taken (often a table or callback) |
| External | Import thunk / external location |
| Indirect | Recovered computed target (when analysis succeeded) |

`X` on an address opens incoming xrefs. The listing also shows a compact
xref suffix on many rows.

### How to use them

- **From a string** to the code that prints it
- **From an import** to every caller of `WinHttpSendRequest` / `connect`
- **From a global** to every reader and writer (state machines)
- **From a function** to callers (blast radius)

Missing xrefs are normal for obfuscated or computed control flow. Extra
xrefs appear when a constant happens to equal an address. Confirm in
context.

### Reference management

You can add or delete references when you have proven a target the
analyzers missed (jump tables, handwritten dispatch). Do that sparingly
and comment why.

### Checkpoint

- A constant `0x401000` is both an address and a magic size. How do you
  decide whether an xref should exist?
- Why are incoming xrefs to a string often a better starting point than
  `main`?

---

## Chapter 10: Using Graph Views

### Function Graph

Basic-block graph of the current function. Each node is a straight-line
sequence; edges are branches. Use it when nested `if`/`goto` soup hides
the real shape: diamonds (if/else), loops with a single back-edge,
dispatch nodes with many out-edges (switches).

Layout options matter on large functions. Isolated nodes often mean
analysis thinks code is reachable when it is not, or the reverse.

### Function Call Graph

Functions as nodes, calls as edges. Start from `main`, `DllMain`, or an
interesting import and walk *out* (callees) or *in* (callers).

This is a map, not a proof. Indirect calls may be missing. Thunks can
make libraries look like local code.

### Other graphs

Ghidra also exposes data-flow / p-code oriented views in some tools and
in the Debugger. Use them when the listing is correct but you still
cannot see *why* a value reaches a call.

### Practical habit

Graph to choose a region, listing to verify bytes, decompiler to explain
the region, types to make the explanation stable.

### Checkpoint

- A Function Graph shows a block with no predecessors and no successors.
  What are the two most likely causes?
- When is a call graph *more* misleading than no graph at all?

---

# Part III: Customizing and Extending Ghidra

## Chapter 11: Using Ghidra Collaboratively

### Why a server exists

Ghidra was built for teams that must share a large program database:
check-out / check-in, merging of user markup (names, comments, types),
and a shared repository instead of emailing `.gzf` archives.

Docs live in the install: `server/svrREADME.html`.

### Roles

- **Server process:** hosts repositories, authenticates users
- **Shared project:** client view of a repository
- **User markup:** names, comments, bookmarks, types you add

Not everything merges cleanly. Coordinate who owns a function range
during a live incident.

### Client workflow (conceptually)

1. Admin stands up the server and creates a repository.
2. Analysts create a **Shared Project** pointing at `ghidra://host:port/repo`.
3. Check out a program, analyze, check in with a message.
4. Update to pull others' markup.

Headless can import and commit to a server with `-connect`, `-p`, and
`-commit` (Chapter 16).

### When not to use a server

Solo CTF, disposable malware detonation, or classified material that
cannot leave a single host. Use a non-shared project and archive the
`.gpr` + `.rep` pair.

### Checkpoint

- What exactly is being shared: the original bytes, the analysis
  database, or both?
- Why must every client version match closely on a shared repository?

---

## Chapter 12: Customizing Ghidra

### Tools vs. projects vs. programs

- **Program:** one imported binary plus its analysis DB
- **Project:** container of programs and folders
- **Tool:** a configured collection of plugins (CodeBrowser is a tool)

Save your docking layout and key bindings into the tool. Export `.tool`
files for the team.

### Configuration surfaces

| Surface | What you change |
| --- | --- |
| **File → Configure** | Enable/disable plugins (BSim, Debugger pieces, visualizers) |
| **Edit → Tool Options** | Colors, listing fields, analyzer defaults, key bindings |
| `support/launch.properties` | JVM heap, Java home override, UI workarounds |
| Front-end **Edit → Options** | Project window behavior |

Raise heap for large firmwares, for example by adding a `VMARGS=-Xmx` line
in `launch.properties` (read the comments in that file first).

### Analyzer defaults

If you always disable an analyzer that wrecks a certain firmware family,
change the default for *your* tool, not ad hoc every import.

### Themes and fonts

High-density listing work needs a monospace font you can read for four
hours. Set it once. Contrast matters more than aesthetics.

### Checkpoint

- You enabled a plugin and CodeBrowser will not start. What is the
  recovery path that does not delete your project?
- Why is a customized *tool* more portable than a customized *program*?

---

## Chapter 13: Extending Ghidra's Worldview

"Worldview" means: what Ghidra is allowed to know about formats, types,
and processors it did not ship with.

### Extension points (conceptual)

| Extension | You add this when… |
| --- | --- |
| Data type archive | The vendor has a stable ABI |
| Analyzer plugin | You repeat the same recovery (C-string tables, custom headers) |
| Loader (Ch. 17) | The container format is new |
| Processor / language (Ch. 18) | The ISA is new or incomplete |
| Exporter | You need a non-standard output |
| Script (Ch. 14) | The task is one-off or batch |

### Installing extensions

Official and community extensions drop into the user extension directory
or are built with Gradle against a Ghidra install. Enable them from the
front-end **File → Install Extensions**. Restart the tool.

Only install extensions you can review. They run with Ghidra's privileges
on the files you import.

### Type archives as the first extension

Before you write Java, export a `.gdt` of the structs you keep rebuilding.
That is an extension of worldview in the smallest sense.

### Checkpoint

- A script, an analyzer, and a loader can all create functions. How do
  you choose which one to write?
- Why is "install this random `.zip` extension" an OPSEC question?

---

## Chapter 14: Basic Scripting with Ghidra and PyGhidra

### Two runtimes

**Java GhidraScript** is the native plugin language. Scripts extend
`GhidraScript`, implement `run()`, and get `currentProgram`,
`currentAddress`, `currentSelection`, and `monitor`.

**PyGhidra** is official CPython 3 access through JPype. Launch the GUI
with `support/pyghidraRun`, or use `pyghidra` as a library. Jython-era
scripts may need edits.

### Script Manager

**Window → Script Manager.** Filter by category. Run, edit, or bundle
scripts. User scripts live in your Ghidra user directory so they survive
re-installs.

### Java skeleton

```java
// Rename selected functions with a prefix.
// @category PNWC.Examples

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

public class PrefixSelectedFunctions extends GhidraScript {
    @Override
    public void run() throws Exception {
        String prefix = askString("Prefix", "Prefix to add", "lab_");
        FunctionIterator it = currentProgram.getFunctionManager()
            .getFunctions(currentSelection, true);
        while (it.hasNext() && !monitor.isCancelled()) {
            Function f = it.next();
            String name = f.getName();
            if (!name.startsWith(prefix)) {
                f.setName(prefix + name,
                    ghidra.program.model.symbol.SourceType.USER_DEFINED);
            }
        }
    }
}
```

### PyGhidra as a library

```python
# Requires a matching Ghidra install and pyghidra package.
import pyghidra

pyghidra.start()  # or start(install_dir="/opt/ghidra")

# See the PyGhidra README in
# Ghidra/Features/PyGhidra/src/main/py/README.md
# for current open_project / analyze helpers for your version.
```

Launch helpers:

```bash
# GUI with CPython interpreter
./support/pyghidraRun          # Linux / macOS
support\pyghidraRun.bat        # Windows

# Offline wheel from a release (no PyPI required)
python3 -m pip install --no-index \
  -f "<GhidraInstallDir>/Ghidra/Features/PyGhidra/pypkg/dist" \
  pyghidra
```

### Rules that keep scripts safe

- Honor `monitor.isCancelled()`.
- Do not hard-code absolute addresses from one sample into a "generic" script.
- Log what you change. Markup without a trail is how teams fight themselves.

### Checkpoint

- Why might a Jython script that "worked in 2020" fail under PyGhidra?
- When is a script the wrong tool compared to a type archive?

---

## Chapter 15: Integrated Scripting with Eclipse and GhidraDev

### Why an IDE

Script Manager is enough for twenty-line fixes. The moment you need
breakpoints, Java language services, or a module with several classes,
use an IDE.

Official path: the **GhidraDev** Eclipse plugin, documented under
`Extensions/Eclipse/GhidraDev/` in a release. Ghidra can also generate a
**VS Code module project** from **Tools → Create VSCode Module project**.

### Typical Eclipse loop

1. Install a supported Eclipse and the GhidraDev plugin.
2. Point GhidraDev at your Ghidra installation.
3. Create a script or module project.
4. Launch CodeBrowser or Headless from a run configuration so the
   classpath matches the target Ghidra version.

### Modules vs. scripts

| | Script | Module / extension |
| --- | --- | --- |
| Lifetime | Run once | Loaded as a plugin |
| UI | Dialogs you call | Windows, actions, analyzers |
| Distribution | `.java` / `.py` file | Extension zip |
| Version coupling | Loose | Tight to Ghidra API |

Build extensions against the *same* Ghidra minor version you run.

### Checkpoint

- Your module compiles and does nothing in CodeBrowser. Which
  configuration step is easy to skip?
- Why is "works on my Eclipse" not the same as "works headless in CI"?

---

## Chapter 16: Running Ghidra in Headless Mode

Headless analysis is how you put Ghidra in a pipeline: ingest a folder,
analyze, run scripts, write artifacts, optionally delete the scratch
project.

Launcher: `support/analyzeHeadless` (`.bat` on Windows).
Full flag list: `support/analyzeHeadlessREADME.html` in the install.

### Shape of the command

```text
analyzeHeadless <project_location> <project_name>[/<folder>]
    | ghidra://<server>[:<port>]/<repository>[/<folder>]
    [-import <file-or-dir> | -process <project_file>]
    [-preScript <name> [args...]]
    [-postScript <name> [args...]]
    [-scriptPath "<p1;p2>"]
    [-overwrite] [-recursive] [-readOnly] [-deleteProject]
    [-noanalysis] [-processor <lang>] [-cspec <compiler>]
    [-analysisTimeoutPerFile <seconds>]
    [-connect <user>] [-p] [-commit ["comment"]]
```

### Local examples

```bash
# Import and analyze one file into a new/existing project
./support/analyzeHeadless \
  /home/analyst/ghidra_projects Lab1 \
  -import /home/analyst/samples/utility.bin

# Recurse a directory, cap analyzer time, run a post-script
./support/analyzeHeadless \
  /home/analyst/ghidra_projects Batch \
  -import /home/analyst/samples \
  -recursive \
  -analysisTimeoutPerFile 300 \
  -scriptPath /home/analyst/ghidra_scripts \
  -postScript ExportExports.java /tmp/exports.txt

# Process an already imported program; do not write
./support/analyzeHeadless \
  /home/analyst/ghidra_projects Lab1 \
  -process utility.bin \
  -readOnly \
  -postScript ListFunctions.java
```

### Shell traps

Quote wildcards so the *shell* does not expand them:

```bash
./support/analyzeHeadless /projects Lab1 -process 'a*' -recursive
```

### Server example

```bash
./support/analyzeHeadless \
  ghidra://ghidra.lab.example:13100/MalwareRepo/inbox \
  -connect analyst \
  -p \
  -import /inbox/sample.bin \
  -commit "Initial auto analysis"
```

### What headless is bad at

Anything that needs a human to resolve an indirect jump. Use headless for
triage and extraction; reserve CodeBrowser for the functions that matter.

### Checkpoint

- `-import` versus `-process`: which one expects the file to already live
  in the project?
- Why is `-deleteProject` useful in CI and dangerous on an analyst
  workstation?

---

# Part IV: A Deeper Dive

## Chapter 17: Loaders

A **loader** maps a file into Ghidra's memory model: blocks with
addresses, permissions, names, symbols, entry points, and format-specific
metadata.

### What a loader must decide

- Image base and whether relocations apply
- Which byte ranges become initialized blocks
- External symbol stubs (imports)
- Entry points the analyzer is allowed to start from
- File-format structures worth defining immediately

If the loader is wrong, every later analyzer is decorating fiction.

### Built-in loaders

PE, ELF, Mach-O, COFF, Java class/DEX (where shipped), Intel Hex, raw
binary, and many firmware-adjacent formats. The importer list on your
install is the authority.

### Raw binaries

Firmware often arrives with no container. You provide:

- Language / compiler spec
- Base address (from a manual, a vector table, or a leak)
- Block structure (flash vs. RAM)

Wrong base address is the classic firmware failure: every pointer in the
listing is consistently skewed.

### Writing a loader (when you must)

A custom loader is a Ghidra module that recognizes a magic header and
creates `MemoryBlock`s. Do this only after a one-off raw import plus
scripts has proven the layout. Loaders are for formats you will see
again.

### Checkpoint

- Two RAM blocks overlap after import. Which component is at fault —
  processor, decompiler, or loader?
- Why can a correct ELF loader still produce a useless listing on a
  statically packed sample?

---

## Chapter 18: Processors

A **processor module** (language) teaches Ghidra how bytes become
instructions. Ghidra languages are specified in **SLEIGH**: constructors
that map bit patterns to p-code.

### Language IDs

Example: `x86:LE:64:default`

- Processor family
- Endianness
- Size
- Variant

The **compiler spec** (`gcc`, `windows`, `appchar`) sits beside the
language and describes ABI details: stack pointer, calling conventions,
relocations.

### P-code

P-code is Ghidra's internal RISC-like IR. Each machine instruction
lifts to one or more p-code ops (`COPY`, `INT_ADD`, `LOAD`, `STORE`,
`CALL`, `CBRANCH`, …). The decompiler and many analyzers speak p-code,
not x86.

If SLEIGH lifts a conditional move incorrectly, the decompiler will lie
in a very consistent way.

### When languages are incomplete

Symptoms:

- Disassembly stops at an unknown opcode
- Assembler (Chapter 22) rates the language below "Platinum"
- Context-sensitive prefixes (Thumb vs. ARM, delay slots) flip randomly

Fix path: correct or extend SLEIGH, do not patch the decompiler first.

### Checkpoint

- ARM Thumb code imported as ARM ARM will still "disassemble." Why is
  that worse than a hard failure?
- What does endianness change besides byte order of immediates?

---

## Chapter 19: The Decompiler

### Pipeline (conceptual)

1. Lift instructions to p-code
2. Recover control flow (blocks, loops, switches)
3. Recover data flow and local variables
4. Fold expressions, infer types, emit C-like text

Every stage depends on the previous one. Bad function bounds (Ch. 7)
or bad types (Ch. 8) show up as unreadable C.

### What "good C" means

Readable decompiler output is a *consistency check*, not source recovery.
Identical C from two functions does not mean identical source. It means
similar p-code after normalization.

### Common failure modes

| Output | Likely cause |
| --- | --- |
| `unaff_ESI` / leftover registers | Missed saved-register analysis or custom convention |
| Huge `switch` of nonsense | Jump table not recovered |
| `in_FS_OFFSET` soup | TLS / segment registers not modeled |
| Infinite nested casts | Wrong pointer depth or structure |
| Function does not return | Missing `noreturn` or fall-through into data |

### Working with the decompiler

- Click through to listing before you trust a call target
- Fix types at the *source* of a value, not only at the use
- Highlighting a token shows the defining p-code; use that when C is
  too pretty to be true
- Commit comments and names in the program DB; the C text itself is
  generated on demand

### Checkpoint

- Why does renaming a struct field change decompiler output in functions
  you did not touch?
- When should you ignore the decompiler and stay in p-code / listing?

---

## Chapter 20: Compiler Variations

Compilers are opinionated stylists. The same `if` becomes different
bytes under GCC, Clang, MSVC, ICC, and different optimization levels.

### Patterns worth recognizing

| Source idea | Frequent compiled shape |
| --- | --- |
| `if (p) use(p->x)` | Test + short-circuit branch; MSVC may invert |
| `for (i=0;i<n;i++)` | Count-up or count-down; strength-reduced pointers |
| `switch` | Jump table, binary tree of compares, or both |
| `?:` | `CMOV` or branch |
| Struct return | Hidden pointer argument (`sret`) |
| Exception-heavy C++ | Personality functions, LSDA tables, filter thunks |
| PIC / PIE | RIP-relative LEA on x86-64; GOT/PLT on ELF |

### Inlining and thunks

Aggressive inlining deletes the function you expected to xref. Thunks
(`JMP target`) exist for imports, tail calls, and incremental linking.
Mark thunks as thunks so call graphs skip the trampoline.

### Stack cookies, CFG, CET

Security instrumentation adds calls you must not confuse with product
logic: `__security_check_cookie`, CFG dispatch, CET landing pads.
Type them and name them early so they disappear from your mental load.

### Matching a compiler spec

Wrong compiler spec → wrong calling convention → wrong decompiler
arguments. If a Windows driver was imported with `gcc`, fix the spec
before "fixing" every function.

### Checkpoint

- A loop increments a pointer by 16 each iteration. What C is more
  likely than `i++` on an `int`?
- Why do two binaries from the same source and different `-O` levels
  defeat naive byte-level diffing?

---

# Part V: Real-World Applications

## Chapter 21: Obfuscation and Emulation

> [!CAUTION]
> This chapter is about *recognizing and working through* protective
> layers on binaries you are authorized to analyze. It is not a recipe
> for building packers or evading defenses.

### What obfuscation does to Ghidra

Obfuscation attacks the assumptions in Chapters 1, 7, 9, and 19:

- Linear and even recursive disassembly miss real control flow
- Xrefs point at decoys
- The decompiler emits correct-but-useless graphs (MBA expressions,
  opaque predicates, bogus loops)
- A small stub is the only real code until something unpacks the rest

### Analyst sequence (authorized lab)

1. Prove you are looking at a stub: tiny `main`, imports like
   `VirtualAlloc` / `mprotect` / `mmap`, encrypted payload section.
2. Find the transformation that produces executable bytes (copy,
   decrypt, map).
3. Capture the *result* of that transformation — dump from a controlled
   debug session or emulator — and import the dumped image as a new
   program or overlay.
4. Re-analyze the dumped image. Do not spend days deobfuscating the
   stub if the payload is sitting in memory after one run.

### Emulation inside the SRE workflow

Ghidra's p-code can drive emulation-style reasoning (and the Debugger
can drive real processes). Emulation is useful when you need to
evaluate a decoder loop without giving the sample a live network.

Keep emulation in the lab VM. Treat emulator traces as evidence that
still needs confirmation on the dumped bytes.

### Opaque predicates and junk

If a branch is statically always taken, undefine the dead side so the
function graph and decompiler stop pretending it matters. If you cannot
prove it, leave it and bookmark it.

### Checkpoint

- Why is "the decompiler looks ugly" not the same as "the binary is
  packed"?
- What do you lose if you only analyze the packed file and never the
  dumped image?

---

## Chapter 22: Patching Binaries

> [!CAUTION]
> Patching changes program behavior. Only patch binaries you are
> allowed to modify (your lab builds, owned firmware, authorized test
> articles). Shipping a patched third-party binary can violate license
> and integrity policies even when the analysis was legal.

### What Ghidra patches

Ghidra patches the **program database** first: the bytes in a memory
block. Exporting those bytes back to a loadable file is a separate
step.

### Instruction and data patching

From the Listing:

- **Patch Instruction** — mnemonic editor backed by the SLEIGH
  assembler. First use for a language may be slow. Completing a
  suggested byte sequence writes the new encoding.
- **Patch Data** — encode a value with the current data type.
- **Assemble...** — multi-line assembly into a range.

Shortcut commonly bound: `Ctrl+Shift+G` for Patch Instruction
(confirm on your key bindings).

The assembler quality depends on the processor module. Languages rated
below Platinum may reject legal encodings or pick unexpected variants.

### Practical constraints

- Replacement instruction must usually fit the original length, or you
  must relocate and add a jump. Ghidra will not magically expand a PE
  section for you.
- Patching `JZ` to `JMP` changes more than a flag check; update your
  comments and consider downstream integrity checks.
- Relocations, checksums, signatures (Authenticode), and packed
  payloads can all undo or reject a patch at runtime.

### Getting bytes back out

Use a built-in exporter that matches the format, or a script that
writes a block range to disk. Verify the export with `sha256sum`
against the original and with `file` / a loader test in the lab.

### Checkpoint

- You replaced a 2-byte instruction with a 5-byte one in place. What
  did you almost certainly overwrite?
- Why is a successful listing patch not evidence that the *file on
  disk* changed?

---

## Chapter 23: BSim and Other Comparison Tools

### Version tracking and diffs

Ghidra can compare two programs (Version Tracking / Program Diff) to
match functions after a patch release, a rebuild, or light
obfuscation. Byte-identical matching is the easy case. The useful case
is "this function moved and was recompiled."

Workflow idea:

1. Analyze both versions to a similar quality.
2. Seed matches: exact bytes, exact names, unique constants.
3. Propagate via call-graph context.
4. Inspect unmatched functions — that is the behavioral delta.

### BSim (Behavioral Similarity)

[BSim](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass/BSim)
is a Ghidra feature that indexes **decompiler-derived feature vectors**
for functions. Functions with similar control/data-flow features score
as similar even across compilers, architectures, or small source
changes.

Components:

- **BSim client:** CodeBrowser with `BSimSearchPlugin` enabled
  (`File → Configure`)
- **BSim database:** stores signatures + metadata (file-backed H2 for
  labs; heavier backends for large corpora)
- **Command-line `support/bsim`:** `generatesigs` and `commitsigs`

Official class outline:

1. Enable the plugin
2. Create and populate a database
3. Query from **BSim → Search Functions...**
4. Evaluate matches (score is similarity, not identity)
5. Optional: command-line ingest, filters, feature visualizer

### How to think about a match

A high BSim score means "these lifted behaviors share many features."
It does not mean "same author" or "same malware family" by itself.
Combine with strings, types, and call-graph neighborhood.

### Other comparison tools in the same lab

| Tool | Compares | Weakness |
| --- | --- | --- |
| `cmp` / `sha256sum` | Whole file | Any rebuild defeats it |
| `bindiff`-style graph matchers | CFG / call graphs | Setup cost |
| `radiff2` | Bytes / blocks | Weak on heavy compile change |
| YARA | Byte / string patterns | Needs a human-written rule |
| BSim | Decompiler features | Needs good decompilation first |

### Checkpoint

- Why does BSim get *worse* if you skip type cleanup before ingest?
- When is a whole-file hash the right comparison tool, and when is it
  theater?

---

# Appendix: Ghidra for IDA Users

A mapping, not a value judgment.

| IDA habit | Ghidra counterpart |
| --- | --- |
| IDB / i64 database | Project + program DB (`.gpr` + `.rep`) |
| IDC / IDAPython | Java GhidraScript + PyGhidra (CPython 3) |
| Hex-Rays | Built-in decompiler pane |
| `n` rename | `L` rename |
| `u` undefine | `U` undefine |
| `c` code | `D` disassemble |
| `x` xrefs | `X` xrefs |
| `g` goto | `G` goto |
| `y` type | `T` / `Y` types |
| Signatures / FLIRT | FID / type archives / BSim (different theory) |
| Local types | Data Type Manager + `.gdt` archives |
| IDC batch | `analyzeHeadless` + `-preScript` / `-postScript` |
| Lumina / cloud names | Shared Ghidra Server markup; BSim corpora |
| Graph view | Function Graph / Call Graph |
| Patch → apply | Patch Instruction / Assemble, then export |
| Plugins | Extensions + `File → Configure` |

Mental-model shifts that save a week:

- Ghidra wants a **project** first. There is no "just open the file"
  that is not also creating database state.
- Types are first-class and shared. Spend more time in the Data Type
  Manager than you did in IDA local types.
- The decompiler is always there. Use it early, but keep the listing
  as the court of appeal.
- Collaboration is a server, not a copied IDB.

---

## Lab appendix: first-session checklist

Use a binary you are allowed to analyze (your own build, a packaged
GhidraClass exercise, or a public corpus with a clear license).

1. Record `java -version` and Ghidra version from **Help → About**.
2. Create a non-shared project.
3. Import. Confirm language + compiler spec against `file` / `readelf`.
4. Run default analysis.
5. List imports and strings. Write three sentences on what the program
   *appears* to do.
6. Open the real entry (`main` or equivalent). Rename it if needed.
7. Fix one wrong type and watch the decompiler change.
8. Follow one string xref to a function. Name the function.
9. Open that function in the Function Graph. Bookmark the error path.
10. Export a `.gdt` of any struct you created. That is your first
    reusable artifact.

---

## Official sources

- Ghidra source and releases: [github.com/NationalSecurityAgency/ghidra](https://github.com/NationalSecurityAgency/ghidra)
- Getting Started (versioned with the tree): [GhidraDocs/GettingStarted.md](https://github.com/NationalSecurityAgency/ghidra/blob/master/GhidraDocs/GettingStarted.md)
- Class material: [GhidraDocs/GhidraClass](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass)
- BSim class: [GhidraDocs/GhidraClass/BSim](https://github.com/NationalSecurityAgency/ghidra/tree/master/GhidraDocs/GhidraClass/BSim)
- PyGhidra: `Ghidra/Features/PyGhidra/` in the same repository
- Headless flags: `support/analyzeHeadlessREADME.html` inside a release
- Server: `server/svrREADME.html` inside a release
- In-app Help remains authoritative for UI labels on *your* build

## See also

- [Reverse Engineering section index](./README.md)
- [LEGAL.md](../LEGAL.md)
- [GLOSSARY.md](../GLOSSARY.md)
- [Homelab](../Homelab/)
- [HardwareHacking](../HardwareHacking/)
- [IncidentResponse](../IncidentResponse/)

---
[Back to Master Index](../README.md) | [Role Navigation](../START_HERE.md) | [Legal Notice](../LEGAL.md)
