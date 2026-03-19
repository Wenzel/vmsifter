# Vision & Architecture Direction

This document captures the intended goals, flows, and architectural direction for VMSifter.

## What VMSifter Is

VMSifter is a **CPU instruction testing framework**. It injects x86 instructions into controlled execution environments, collects execution results (VMEXIT reason, registers, performance counters), and outputs structured CSV data.

## Core Goals

1. **Instruction discovery**: Enumerate the full x86 instruction space on real hardware, identifying valid encodings, their lengths, and behavior
2. **Differential testing**: Execute the same instruction set across multiple backends (hypervisors, emulators, bare metal) and compare results to surface discrepancies — undocumented behavior, errata, emulator bugs, spec violations
3. **Microarchitectural fingerprinting**: Use performance counter deltas to characterize instruction behavior at the microarchitectural level

## Two Axes, Three Phases

VMSifter's workloads are organized along two independent axes, producing three distinct phases.

### Discovery axis: per CPU model

The Tunnel fuzzer explores the x86 instruction space byte-by-byte, using EPT execute faults to distinguish complete from incomplete instructions. This **requires real-time feedback** from an execution backend — the next probe depends on the previous result.

- Requires an EPT-capable backend (Xen VM forking, or KVM)
- Tightly coupled fuzzer ↔ injector loop
- Output: CSV of all discovered valid instruction encodings

The relevant variable is **CPU model**, not hypervisor. The same physical CPU produces the same instruction set regardless of whether Xen or KVM intercepts the VMEXIT — the silicon decodes the same way. Running Tunnel on Xen on an Intel Ice Lake and on KVM on the same Ice Lake discovers the same instructions; the hypervisor only affects how results are reported, not what the CPU accepts.

Therefore: **run Tunnel once per CPU model** (Intel SKL, Intel ICL, AMD Zen3, ...), on whichever hypervisor is available. Running Tunnel on a second hypervisor on the same CPU adds no discovery value.

Emulators have their own software decoders, so in theory Tunnel could discover what each emulator considers valid — including "false positive" instructions the emulator wrongly accepts. In practice, this is not worth the cost: emulators are orders of magnitude slower than real hardware with VM forking, and CSV replay already catches the important direction (does the emulator handle all *real* instructions correctly?). The marginal value of discovering emulator-only bogus instructions rarely justifies the runtime.

```{mermaid}
flowchart LR
    T1["Tunnel + Xen (Intel ICL)"] --> C1["catalog_intel_icl.csv"]
    T2["Tunnel + KVM (AMD Zen3)"] --> C2["catalog_amd_zen3.csv"]
    T3["Tunnel + Xen (Intel SKL)"] --> C3["catalog_intel_skl.csv"]
    C1 & C2 & C3 --> U["master_instruction_catalog.csv"]
```

### Testing axis: per backend

Once a master instruction catalog exists (from Tunnel discovery, manual curation, or external sources like Intel XED's instruction tables), the remaining work is pure **replay**: inject each instruction, collect results, dump CSV. The next instruction does not depend on the previous result.

- Any backend works: hypervisors (Xen, KVM), emulators (QEMU, Unicorn, Simics, Bochs), decoders (XED, bddisasm, Zydis), bare metal
- No fuzzer ↔ injector coupling needed — just iterate over the input CSV
- Output: per-backend CSV result files
- Run across as many backends as desired

This is what enables differential testing: replay the same instruction catalog on every backend and diff the outputs.

```{mermaid}
flowchart LR
    CAT["master_instruction_catalog.csv"] --> X["Xen (Intel ICL)"]
    CAT --> K["KVM (AMD Zen3)"]
    CAT --> Q["QEMU TCG"]
    CAT --> B["Bochs"]
    CAT --> XED["XED"]
    CAT --> BD["bddisasm"]
```

### Phase 3: Analysis (external)

Comparing CSV result files across backends, CPUs, and configurations. This is **not VMSifter's job** — it should happen in external tooling better suited for data analysis (pandas, DuckDB, Jupyter notebooks, custom diffing tools, visualization).

VMSifter's responsibility ends at producing clean, well-structured CSV output.

## Scope Boundary: What Lives Inside VMSifter

The guiding principle: **VMSifter handles backends that require privileged, stateful VM lifecycle management.** Everything that is a userspace function-call-per-instruction belongs in separate tooling. The CSV file format is the interface between VMSifter and external tools.

```{mermaid}
flowchart TD
    subgraph VMSifter ["VMSifter (privileged VM lifecycle)"]
        FZ["Fuzzers: Tunnel, Random, CSV, Drizzler"]
        IJ["Injectors: Xen, KVM"]
    end
    VMSifter -->|"CSV files"| D["Decoders (XED, bddisasm, Zydis)"]
    VMSifter -->|"CSV files"| EM["Emulators (Unicorn, QEMU, Bochs, Simics)"]
    VMSifter -->|"CSV files"| AN["Analysis (pandas, DuckDB, Jupyter)"]
```

### Inside VMSifter: Hypervisor Injectors

Hypervisor-based execution requires privileged, stateful VM lifecycle management — exactly what VMSifter's scaffolding exists to handle: VM creation/forking, CPU pinning, VMEXIT interception, register canary management, EPT/NPT permission control, performance counter MSR access, and cleanup.

| Backend | Status | EPT/NPT | VM Forking | Notes |
|---------|--------|---------|------------|-------|
| **Xen** | Current | Yes (EPT) | Yes (`xc_memshr_fork`) | Primary backend, requires custom Xen patches |
| **KVM** | Planned | Yes (EPT + NPT) | See below | Mainline Linux, no patches needed |

**Why KVM belongs inside VMSifter:**

- Same class of problem as Xen: privileged VM lifecycle, VMEXIT interception, register/MSR management
- Shares VMSifter infrastructure: PCPU allocation, CPU pinning, worker parallelism, CSV output
- **Primary motivation**: enables Tunnel discovery on AMD CPUs (NPT), which Xen's current C injector doesn't support
- **Secondary benefit**: no custom hypervisor patches — ships with mainline Linux, simpler deployment

**KVM implementation challenges:**

The current C injector is deeply Xen-specific (`xc_memshr_fork()`, Xen domctl for MSRs, XTF for guest setup). A KVM injector would need:

- VM creation via `ioctl` on `/dev/kvm` instead of Xen toolstack
- Guest setup without XTF (minimal flat binary or direct register/memory setup via KVM API)
- State reset mechanism — this is the key challenge:

| Approach | Speed | Complexity | Notes |
|----------|-------|------------|-------|
| **Dirty page tracking + register reset** | Fast | Moderate | `KVM_GET_DIRTY_LOG` to find modified pages, restore only those. Approximate fork-reset. |
| **Full snapshot/restore** | Slow | Simple | Save all state, restore after each instruction. Correct but expensive. |
| **KVM + userfaultfd** | Fast | High | COW-like behavior via userspace fault handling. Closest to Xen fork semantics. |

**Hyper-V**: Low priority. Windows-only, different ecosystem. Could be a future injector if there's demand.

### Outside VMSifter: Disassemblers / Decoders

Disassemblers are pure functions: `bytes → metadata`. They don't execute instructions, don't need VMs, sockets, or privileges. A standalone Python script iterating over CSV rows processes millions of instructions per second. VMSifter's scaffolding would be pure overhead.

**These belong in a separate tool** that reads VMSifter's instruction CSV and produces decoder result CSVs.

| Backend | Source | Output |
|---------|--------|--------|
| **XED** (Intel) | Intel's reference x86 encoder/decoder | Validity, instruction length, operand registers (read/written), EFLAGS modified, category, ISA set, operand width |
| **bddisasm** (Bitdefender) | Independent x86 decoder | Validity, length, operand details, CPUID feature flags required |
| **Zydis** (Zyantific) | Fast open-source decoder | Validity, length, operand details, accessed flags |

**XED is particularly interesting** because it is Intel's own reference decoder. When VMSifter executes an instruction on real Intel hardware and XED decodes the same bytes, any discrepancy is a strong signal:

- **Length mismatch**: CPU decoded N bytes, XED says M → potential undocumented encoding or decoder bug
- **Register side effects**: CPU modified registers that XED doesn't list as outputs (or vice versa) → undocumented behavior or errata
- **EFLAGS delta**: CPU modified flags that XED says shouldn't be affected → microarchitectural leak or spec gap
- **Validity disagreement**: CPU executes bytes that XED calls invalid (or CPU faults on bytes XED calls valid) → undocumented instruction or decoder gap

### Outside VMSifter: Emulators

Emulators are userspace-only and don't benefit from VMSifter's scaffolding. For CSV replay (the primary mode for emulators), the per-instruction loop is trivial — a thin wrapper around each emulator's API:

```python
# Unicorn example — the entire core loop
uc = Uc(UC_ARCH_X86, UC_MODE_64)
uc.mem_map(CODE_ADDR, 0x1000)
for insn_bytes in csv_reader:
    uc.mem_write(CODE_ADDR, insn_bytes)
    set_canary_registers(uc)
    try:
        uc.emu_start(CODE_ADDR, CODE_ADDR + len(insn_bytes), count=1)
    except UcError as e:
        fault_type = e.errno
    regs = read_all_registers(uc)
    csv_writer.write(insn_bytes, fault_type, reg_delta(regs))
```

What VMSifter would add: `ProcessPoolExecutor` parallelism — but a simple `multiprocessing.Pool` does the same without needing CPU pinning. What VMSifter would impose: Unix socket protocol, C subprocess, Xen-centric configuration — all overhead for something that's a Python function call.

**These belong in a separate tool** that reads VMSifter's instruction CSV and produces emulator result CSVs.

| Backend | Fidelity | Speed | Notes |
|---------|----------|-------|-------|
| **QEMU** (TCG) | Instruction-level | Moderate | Full system emulation, well-understood gaps vs real HW |
| **Unicorn** | Instruction-level | Fast | Lightweight, API-friendly, based on QEMU TCG |
| **Bochs** | Cycle-approximate | Slow | Most faithful x86 emulator, good reference |
| **Simics** | Cycle-accurate | Slow | Commercial, high fidelity, scriptable |

### Outside VMSifter: Bare Metal / Ring 0

| Backend | Notes |
|---------|-------|
| **Ring 0 (Linux kernel module)** | Original sandsifter approach, no hypervisor needed |
| **SMM** | System Management Mode execution |

These are execution backends but don't involve VM lifecycle management. Whether they belong inside or outside VMSifter depends on how much shared infrastructure they'd use. This is an open question for later.

### Outside VMSifter: Analysis

Comparing CSV result files across backends, CPUs, and configurations. This is explicitly **not VMSifter's job**. It should happen in external tooling better suited for data analysis (pandas, DuckDB, Jupyter notebooks, custom diffing tools, visualization).

### CSV as the Universal Interface

All backends — whether inside or outside VMSifter — produce and consume CSV files. The CSV schema must:

- Handle both execution backends and decoder backends (optional columns)
- Include backend metadata (which backend, which CPU model, which configuration)
- Support performance counters (optional, only real hardware)
- Support decoder-specific fields: operand details, EFLAGS, ISA set (optional, only decoders)
- Be stable across VMSifter versions to allow cross-version comparison

## Fuzzer × Injector Matrix (within VMSifter)

| Fuzzer | Requires Real-Time Feedback | Compatible Injectors |
|--------|---------------------------|---------------------|
| **Tunnel** | Yes (EPT/NPT faults) | Xen, KVM |
| **Random** | No | Xen, KVM |
| **CSV** (replay) | No | Xen, KVM |
| **Drizzler** | No (but needs memory region setup) | Xen, KVM |

All fuzzer × injector combinations within VMSifter are valid. The Tunnel fuzzer requires EPT/NPT feedback, which all VMSifter injectors provide by definition (they're hypervisors on real hardware).

## End-to-End Differential Testing Flow

```{mermaid}
flowchart LR
    subgraph Discovery ["Discovery (VMSifter)"]
        T1["Tunnel + Xen (Intel ICL)"]
        T2["Tunnel + KVM (AMD Zen3)"]
        T3["Tunnel + Xen (Intel SKL)"]
    end
    T1 & T2 & T3 -->|union| CAT["catalog.csv"]
    subgraph Testing
        CAT --> X["Xen (ICL)"]
        CAT --> K["KVM (Zen3)"]
        CAT --> Q["QEMU TCG"]
        CAT --> B["Bochs"]
        CAT --> XED["XED"]
        CAT --> BD["bddisasm"]
    end
    X & K & Q & B & XED & BD --> DIFF["External diff / analysis"]
```

The decoder path is especially powerful: XED can process the full instruction catalog in seconds and provide Intel's reference answer for length, operands, flags, and validity — a fast, authoritative baseline to diff all execution results against.

## Architectural Decisions

### VMSifter's scope: fuzzers + hypervisor injectors + CSV

VMSifter keeps instruction generation (fuzzers) and hypervisor-based injection. It does **not** grow to include emulator backends, disassembler backends, or analysis tooling. Its output boundary is CSV files.

- **Fuzzers** are instruction sources (Tunnel for discovery, Random/CSV/Drizzler for testing)
- **Injectors** are hypervisor backends requiring privileged VM lifecycle management (Xen, KVM)
- **CSV** is the interface to everything else

### Tunnel stays coupled to hypervisor injectors

Tunnel's algorithm depends on EPT/NPT execute faults for real-time feedback. This cannot be replaced by CSV replay. However, Tunnel only needs to run **once per CPU model** — the instruction set is a property of the silicon, not the hypervisor.

The only reason to add a hypervisor injector is to reach CPU models the existing injectors can't (e.g., KVM for AMD with NPT). Adding emulator or decoder backends does **not** require Tunnel support — only CSV replay, which lives outside VMSifter.

### The C injector needs refactoring for multi-hypervisor support

The current C injector (`src/main.c`) is deeply Xen-specific. To support KVM, the injector layer needs to be split:

- **Common**: instruction injection logic, register canary management, result message format, socket protocol
- **Xen-specific**: `xc_memshr_fork()`, Xen domctl MSR access, XTF guest setup
- **KVM-specific**: `ioctl`-based VM creation, `KVM_GET/SET_REGS`, dirty page tracking for state reset

This refactoring is a prerequisite for KVM support and would also clean up the current codebase.
