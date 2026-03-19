# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Important: Read Documentation First

Before exploring the codebase with broad searches or launching subagents, **always read the existing documentation first**:

- `docs/source/index.md` — documentation index
- `docs/source/reference/architecture.md` — full architecture reference (components, memory layout, protocols, data flow)
- `docs/source/reference/configuration.md` — all configuration keys
- `docs/source/reference/xen-patches.md` — Xen patches required and their purpose
- `README.md` — setup instructions

These docs are comprehensive and will answer most architectural questions without needing to grep through source code.

## Project Overview

VMSifter is a differential fuzzing CPU instruction framework, based on an enhanced sandsifter with performance counter monitoring and ring0 execution capabilities.
It's a research tool for CPU instruction fuzzing that runs on Xen hypervisor with VM forking features. The system generates and executes CPU instructions in virtualized environments to discover undocumented behavior.

## Development Commands

### Setup
```bash
# Install dependencies
poetry install

# Setup Xen (requires root access - see README.md for full setup)
git submodule update --init --recursive
```

### Code Quality
```bash
# Format code (black + isort)
poetry run poe format

# Lint code
poetry run poe lint

# Type checking
poetry run poe typing

# Combined code quality check
poetry run poe ccode
```

### Testing
```bash
# Run all tests with debugger support
poetry run poe pytest

# Run unit tests only
poetry run poe unit_test

# Run benchmark tests
poetry run poe bench_test
```

### Running VMSifter
```bash
# Basic execution
./run.sh

# Direct poetry execution with options
poetry run vmsifter --fuzzer-mode TUNNEL --injector-mode XENVM --jobs 4
```

### Documentation
```bash
cd docs
make html
xdg-open build/html/index.html
```

## Architecture Overview

### Two-Tier Design: Python + C

VMSifter is split into two layers:

- **Python layer** (`vmsifter/`): Orchestration, fuzzing logic, result collection, configuration.
- **C layer** (`src/main.c`, `src/forkvm.c`, `src/vmi.c`): Low-level VM interaction via LibVMI and Xen hypercalls, instruction injection into guest memory, performance counter readout.

The two layers communicate over a **Unix domain socket** (`AF_UNIX`, `SOCK_STREAM`) with a tight synchronous loop: Python sends raw instruction bytes, C injects them into the VM, catches the VMEXIT, collects metrics, and sends back a fixed-size `InjectorResultMessage` (264 bytes).

### Core Components

**SifterExecutor** (`vmsifter/executor.py`): Main orchestrator. Creates a Unix socket and a `ProcessPoolExecutor`. Queries Xen for available PCPUs (excluding Dom0's, optionally filtering SMT siblings). Instantiates the selected fuzzer, partitions its search space across PCPUs, and spawns one Worker + Injector per PCPU. On worker completion, deallocates resources and returns the PCPU to the pool.

**Worker** (`vmsifter/worker.py`): Per-CPU execution loop running in a subprocess. Core loop in `handle_client()`:
1. Receive `InjectorResultMessage` from C injector via socket
2. Convert to `FuzzerExecResult` (Interrupted / NMI / EPT / Other)
3. `gen.send(result)` — feed result to fuzzer generator, get next instruction
4. If result is "final" (not a retry), log to CSV
5. Send instruction bytes to injector via socket
6. Repeat until fuzzer raises `StopIteration`

Each worker logs to `{workdir}/worker_{id}.log` and returns `WorkerStats` on completion (instruction count, exit reason distribution, execution speed).

**Injectors** (`vmsifter/injector/`): Interface between VMSifter and virtualization platforms.

*XenVMInjector* (`vmsifter/injector/xenvm.py`):
- **Once per process** (thread-safe lock): creates a "parent" XTF test VM via the C injector's `--setup` mode. The parent initializes registers with canary values (`0x1100 + offset`) via a magic CPUID leaf (`0x13371337`) and configures performance counters.
- **Per worker**: forks the parent VM using `xc_memshr_fork()` (lightweight COW clone), pins the fork to a specific PCPU, spawns the C injector subprocess in `--socket` mode.

**C Injector** (`src/main.c`):
- Connects to the Unix socket
- Sets up guest memory: deduplicates critical pages (IDT, GDT, stack, code), configures EPT permissions
- Event loop: on each VMEXIT, reads perf counters via `xc_vcpu_get_msrs()`, captures all GP registers + CR2, sends `InjectorResultMessage`, receives next instruction, writes it to guest memory at `0xa000 - insn_size`, resets registers to canary state, resumes with `VMI_EVENT_RESPONSE_RESET_FORK_STATE`

**Fuzzers** (`vmsifter/fuzzer/`): All fuzzers are Python generators (yield/send pattern) so the next instruction can depend on the previous execution result.
- **TUNNEL** (`tunnel.py`): Primary algorithm. Systematically explores x86 instruction space byte-by-byte using a "marker" index. EPT execute fault = incomplete instruction (needs more bytes). Valid instruction triggers backwards search to find shortest encoding. Nibble-skipping optimization after ~10 similar results. Partitionable by first-byte range for parallelism.
- **RANDOM** (`random.py`): Random length + random bytes via `os.urandom()`.
- **CSV** (`csv.py`): Replays instructions from CSV files for differential testing. Can generate prefix variations and compare against baseline.
- **DRIZZLER** (`drizzler.py`): Integration with Drizzler specification-aware fuzzer for mutation-based generation.

### Socket Protocol

```
Worker (Python)                 Injector (C)
     |                               |
     |--- send(instruction bytes) -->|
     |                               | [inject into VM at 0xa000]
     |                               | [VM executes, VMEXITs]
     |                               | [collect regs, perf ctrs, exit reason]
     |<-- send(InjectorResultMessage)-|
     |                               |
  [process result, advance fuzzer]   |
     |         ...repeat...          |
```

- Instruction: 1-15 bytes (configurable `insn_buf_size`)
- Result: 264-byte `InjectorResultMessage` struct containing: VMEXIT reason + qualification, 7 performance counters, 18 registers (17 GP + CR2), GLA, interrupt/vectoring info, instruction size + info fields.

### Result Classification

`FuzzerExecResult` hierarchy based on VMEXIT reason:
- **Interrupted**: external interrupt — retry same instruction
- **NMI**: includes interrupt type, page fault error code, CR2, stack value
- **EPT**: EPT violation with R/W/X qualification (execute fault = incomplete instruction)
- **Other**: all remaining VMX exit reasons (76 possible)

Factory method `FuzzerExecResult.factory_from_injector_message()` maps the C struct to the appropriate Python subclass.

### Output Format

`CSVOutput` (`vmsifter/output.py`) writes per-worker CSV files:
- `results_{id}.csv` — valid instructions
- `invalid_instructions_{id}.csv` — invalid opcodes (separated out)

Columns: `insn` (hex), `length`, `exit-type`, `misc` (cpu_len, insn_info, stack value, page fault EC), `pfct1-7` (perf counter deltas), `reg-delta` (register changes from canary values).

### Data Flow

```
SifterExecutor.run()
  |-- selects Fuzzer + Injector classes
  |-- partitions fuzzer search space across available PCPUs
  |-- for each PCPU:
  |     |-- XenVMInjector: creates/reuses parent VM, forks it (COW), pins to PCPU
  |     |     \-- spawns C injector process (connects via Unix socket)
  |     \-- Worker (in subprocess): runs tight send/recv loop
  |           |-- fuzzer.gen() <-> socket <-> C injector <-> VM fork
  |           \-- CSVOutput logs final results per instruction
  \-- collects WorkerStats, cleans up (destroys forks, returns PCPUs)
```

### Key Configuration

Settings are managed via `vmsifter/config/settings.toml` using Dynaconf. Key settings include:
- `jobs`: Number of parallel workers
- `fuzzer_mode`: Type of instruction generation (TUNNEL, RANDOM, CSV, DRIZZLER)
- `injector_mode`: Virtualization backend (XENVM)
- `insn_buf_size`: Max instruction length (default 15)
- `x86.exec_mode`: 32, 32pae, or 64-bit execution
- `injector.xenvm.perfcts`: Performance counter MSR addresses
- `workdir`: Output directory for results

### File Structure

- `src/`: C injector code — VM interaction, instruction injection, perf counter collection
  - `main.c`: Core logic (setup, event handlers, instruction injection loop)
  - `forkvm.c`: VM forking via `xc_memshr_fork()`
  - `vmi.c`: LibVMI initialization wrapper
- `vmsifter/`: Python package
  - `executor.py`, `worker.py`: Orchestration and per-CPU execution
  - `injector/`: Injector interface + XenVM implementation
  - `fuzzer/`: Fuzzer implementations + result types + search space partitioning
  - `output.py`: CSV result logging
  - `config/`: Dynaconf settings + validators
  - `utils/`: Xen toolstack bindings, completion rate tracking
- `patches/`: Xen hypervisor patches required for VM forking
- `xen/`, `xtf/`, `libvmi/`: Git submodules for dependencies
- `deploy/`: Ansible deployment configuration
- `tests/`: Unit tests (tunnel algorithm, partitioning) and benchmarks

## Important Notes

- Requires custom Xen build with VM forking patches
- Uses Unix domain sockets for Python-C inter-process communication
- CPU affinity pinning via `xl vcpu-pin` for performance isolation
- VM forks use Xen memory sharing (COW) for lightweight cloning
- Registers are initialized with canary values (`0x1100 + offset`) to detect changes
- Performance counters are read via MSRs after each instruction execution
- Results are logged to CSV format in workdir (valid + invalid separated)
- Supports post-mortem debugging with PDB when enabled
- Dynaconf settings are cached in Worker to avoid repeated config access overhead