# Architecture

VMSifter uses a two-tier architecture: a **Python layer** for orchestration, fuzzing logic, and result collection, and a **C layer** for low-level VM interaction, instruction injection, and performance counter readout. The two layers communicate over a Unix domain socket.

## Components

### SifterExecutor

**File:** `vmsifter/executor.py`

The main orchestrator. Responsibilities:

1. Creates a Unix domain socket and a `ProcessPoolExecutor`
2. Queries Xen for available physical CPUs (PCPUs), excluding those allocated to Dom0 and optionally filtering SMT siblings
3. Instantiates the selected fuzzer and partitions its search space across available PCPUs
4. For each PCPU: creates an injector, accepts its socket connection, creates a Worker, and submits it to the process pool
5. On worker completion: deallocates injector + worker, returns PCPU to the available pool, logs statistics

### Worker

**File:** `vmsifter/worker.py`

Runs the per-CPU instruction execution loop in a subprocess. Core loop (`handle_client()`):

1. Receive `InjectorResultMessage` from C injector via socket
2. Convert to a `FuzzerExecResult` subclass (Interrupted / NMI / EPT / Other)
3. Feed result to fuzzer generator via `gen.send(result)`, receiving the next instruction
4. If the result is "final" (not a retry), log it to CSV
5. Send instruction bytes to injector via socket
6. Repeat until the fuzzer raises `StopIteration`

Each worker logs to `{workdir}/worker_{id}.log` and returns `WorkerStats` on completion containing instruction count, exit reason distribution, and execution speed.

### Injectors

**File:** `vmsifter/injector/`

Interface between VMSifter and virtualization platforms.

#### XenVMInjector (`xenvm.py`)

- **Once per process** (protected by a thread-safe lock): creates a "parent" XTF test VM via the C injector's `--setup` mode. The parent VM initializes registers with canary values (`0x1100 + register_offset`) through a magic CPUID leaf (`0x13371337`) and configures performance counters.
- **Per worker**: forks the parent VM using `xc_memshr_fork()` (lightweight copy-on-write clone), pins the fork to a specific PCPU via `xl vcpu-pin`, and spawns the C injector subprocess in `--socket` mode.

#### C Injector (`src/main.c`, `src/forkvm.c`, `src/vmi.c`)

The C injector is the low-level component that directly interacts with the VM:

- **`main.c`**: Core logic including parent VM setup (`setup_parent()`), guest memory preparation (`setup_memory()`), VMEXIT event handler (`exit_cb()`), and the instruction injection loop
- **`forkvm.c`**: VM forking via `xc_memshr_fork()` — creates new HVM domains with HAP and memory sharing
- **`vmi.c`**: LibVMI initialization wrapper

On each VMEXIT, the C injector:
1. Reads performance counters via `xc_vcpu_get_msrs()`
2. Captures all general-purpose registers and CR2
3. Sends the `InjectorResultMessage` (264-byte struct) to the Python worker via socket
4. Receives the next instruction bytes
5. Writes the instruction to guest memory at address `0xa000 - insn_size`
6. Resets registers to canary state
7. Resumes the VM with `VMI_EVENT_RESPONSE_RESET_FORK_STATE`

### Fuzzers

**File:** `vmsifter/fuzzer/`

All fuzzers implement `AbstractInsnGenerator` and use Python generators (yield/send pattern), allowing the next instruction to depend on the previous execution result.

#### TunnelFuzzer (`tunnel.py`)

The primary fuzzing algorithm. Systematically explores the x86 instruction space byte-by-byte using a "marker" index:

- Maintains a position (`marker_idx`) in the instruction byte sequence
- **EPT execute fault** = instruction incomplete, needs more bytes
- **Valid instruction** = check for shortest encoding via backwards search (shorten until EPT fault)
- **Interrupted** = retry same instruction
- Nibble-skipping optimization: after ~10 similar results, skip chunks of the search space
- **Partitionable** by first-byte range for parallelism across workers

#### RandomFuzzer (`random.py`)

Generates random instruction bytes: random length (1 to `insn_buf_size`) filled with `os.urandom()`.

#### CsvFuzzer (`csv.py`)

Replays instructions from CSV files for differential testing. Supports prefix variation generation and baseline comparison (`csv_log_diff_only`).

#### DrizzlerFuzzer (`drizzler.py`)

A specification-aware multi-instruction fuzzer. Where the Tunnel fuzzer generates and executes **one instruction at a time**, Drizzler generates **sequences of multiple instructions** assembled together and executed as a single test case in the VM. This approach is similar to Google's [SiliFuzz](https://arxiv.org/abs/2110.11519) project, which also runs multi-instruction sequences on real CPUs to find hardware issues — though SiliFuzz generates tests by fuzzing a CPU emulator (Unicorn) and compares end state against the emulator's prediction, while Drizzler uses direct specification-aware mutation and detects anomalies through VMEXIT behavior and register/performance counter deltas.

The multi-instruction approach can find issues that single-instruction testing misses: pipeline interactions, state dependencies between instructions, and behavior that only manifests under specific microarchitectural conditions.

**Architecture:**

The fuzzer is built from several cooperating classes:

- **`X86Spec`**: Models the x86 ISA subset used for test generation. Defines register sets across all widths (8/16/32/64-bit, excluding RSP/RBP to avoid corrupting the stack), legacy and REX prefixes, and 6 instruction groups for random background instruction generation: arithmetic (add/sub), data movement (mov), multiplication/division (div/mul), increment/decrement (inc/dec), nop variants, and cache flushing (clflush).

- **`Operand`**: Represents an operand specification with toggleable types — registers, immediates, register-memory references (`WORD PTR [reg + offset]`), and direct memory references (`[0xb000 + offset]`). Generates random concrete operands respecting bitwidth constraints and x86 encoding rules (e.g., avoiding REX + high-byte register conflicts). Memory operands target the 0xB000 region, which the C injector maps with read/write permissions when the `--drizzler` flag is set.

- **`Instruction`**: Pairs a mnemonic with two operands and a prefix list. Builds valid operand combinations per bitwidth to avoid impossible encodings. Generates concrete assembly strings via `getCanonical()`, single-prefix variants via `getSinglePrefixTests()`, and randomly chained prefix variants via `getChainedPrefixTest()`. Supports a custom preparation callback (e.g., `prepareMOVSB` sets up RSI, RDI, RCX before a `movsb`).

- **`Driver`**: The test generation engine. Initialized with a random seed, it:
  1. Builds an **injection pool** from target instructions (and their prefix variants, in aggressive mode)
  2. Generates 0–512 random **background instructions** from the instruction groups
  3. For each target instruction, emits a **test set**: one base test (no prefix) + single-prefix variants + randomly chained prefix variants (up to `maxTestsPerUnit=12` per target)

**Test execution cycle:**

Each test in a test set is run through 6 variations — 2 phases × 3 injection modes:

1. **Base phase** (no injection): the background instructions + target instruction, without randomly injected variants
2. **Injection phase**: same, but target instruction variants from the injection pool are randomly inserted among the background instructions (1% chance per position, up to 6 injections)

Each phase runs in 3 modes:
- **Plain** (type 0): instructions as-is
- **Serialized** (type 1): `lfence` after each instruction
- **Flushed** (type 2): `clflush` for memory operands

The assembly string is converted to machine code using the [Keystone](https://www.keystone-engine.org/) assembler engine. A custom `fix_db_and_assemble()` handler splits out raw prefix bytes (`db 0xNN`) that Keystone cannot assemble directly, assembles the remaining instructions, and stitches the result back together.

**Target instructions** are defined in `DrizzlerFuzzer.setup()`. Currently configured: `lzcnt` (with register and memory operands across 16/32/64-bit widths) and `movsb` (with a preparation function that initializes RSI, RDI, RCX).

**C-side support:** When the `--drizzler` flag is passed to the C injector, it maps additional guest memory pages (0xB000–0x1FFFF) with read/write permissions and fills them with canary bytes (0x41). This supports Drizzler's memory operands which reference `[0xb000 + offset]`.

**Not partitionable** across workers (unlike Tunnel). Test generation is deterministic for a given seed, controlled by `num_seeds`.

## Guest Memory Layout and Setup

The guest VM's memory layout is established in two phases: first by the XTF test harness (which runs inside the guest), then by the C injector (which manipulates the guest from outside via LibVMI).

### Memory Map

The following guest physical address ranges are relevant to VMSifter's operation:

| GPA Range | Size | Purpose | EPT Permissions |
|-----------|------|---------|-----------------|
| `0x0000–0x0FFF` | 4 KB | Null page (guard) | No access (`RWX` denied) |
| `0x1000–0x1FFF` | 4 KB | Low memory (not explicitly managed) | — |
| `0x2000–0x9FFF` | 32 KB | Code region (8 pages) | Read-only (write + execute denied) |
| `0x9FE1–0x9FFF` | up to 15 B | Instruction injection zone (within code page 9) | Same as code region |
| `0xA000` | — | Boundary address: instructions are written *backwards* from here | — |
| `0xB000–0x1FFFF` | 84 KB | Drizzler data pages (only in drizzler mode) | Read+Write (execute denied) |
| IDT base (runtime) | 4 KB | Interrupt Descriptor Table | Read-only (write + execute denied) |
| GDT base (runtime) | 4 KB | Global Descriptor Table | Read-only (write + execute denied) |
| Stack (RSP, runtime) | 4 KB | Guest stack page | Read+Write (execute denied) |
| `0x100000+` | — | XTF binary (`XTF_VIRT_START`) | — |

The IDT, GDT, and stack addresses are not hardcoded — the C injector reads them from the VM's register state (`idtr_base`, `gdtr_base`, `rsp`) after forking.

### EPT Permission Scheme

EPT (Extended Page Tables) permissions control what the guest can do with each physical page. VMSifter restricts permissions to generate precise VMEXITs:

- **Code pages (0x2000–0x9FFF)**: `VMI_MEMACCESS_RW` — execute is allowed, but writes cause an EPT violation. This protects the code region where instructions are injected.
- **IDT/GDT pages**: `VMI_MEMACCESS_WX` — read is allowed, but writes and executes cause EPT violations.
- **Stack page**: `VMI_MEMACCESS_X` — read and write allowed, execute causes an EPT violation.
- **Null page (0x0)**: `VMI_MEMACCESS_RWX` — all access denied, acting as a null pointer guard.
- **Drizzler data pages (0xB000–0x1FFFF)**: `VMI_MEMACCESS_X` — read and write allowed, execute denied. Filled with `0x41` canary bytes.

The key insight is that EPT execute faults on the code region signal that an instruction fetch crossed the `0xA000` boundary — meaning the instruction encoding was incomplete and needed more bytes. The Tunnel fuzzer relies on this to distinguish complete from incomplete instructions.

### Page Deduplication

VM forks created by `xc_memshr_fork()` share all memory pages with the parent via copy-on-write (COW). Before fuzzing begins, the C injector forces deduplication of critical pages using the `page_dedup()` helper:

```c
// Force COW copy, then set EPT permissions
vmi_read_8_pa(vmi, addr, &tmp);       // read from hypervisor
vmi_write_8_pa(vmi, addr, &tmp);      // write back (triggers COW)
vmi_set_mem_event(vmi, addr>>12, perm, 0);  // set EPT permissions
```

This ensures the fork has its own copies of pages that will be modified during fuzzing, and that EPT permissions are correctly configured before the first instruction executes.

### Pagetable Deduplication

In addition to data pages, the C injector deduplicates all guest pagetable pages that map the working address range (0x1000–0x9FFF and the stack). This is critical because x86 processors set Access (A) and Dirty (D) bits in pagetable entries on memory access, which would trigger unwanted EPT violations on shared pages.

The `populate_pagetable_pages()` function walks the guest pagetable hierarchy for each relevant virtual address and deduplicates every level:

- **Legacy (32-bit)**: PGD and PTE pages
- **PAE**: adds PDPE page
- **IA-32e (64-bit)**: adds PML4E page

All pagetable pages are marked with `VMI_MEMACCESS_WX` (read-only), since the processor only needs read access to walk pagetables, but A/D bit updates require write access from the hardware — which VMSifter has already handled by deduplicating the pages.

### Instruction Injection

Instructions are injected into the guest at the boundary of code page 9 (GPA `0x9000–0x9FFF`), written backwards from address `0xA000`:

```
Guest Physical Memory (code page 9):

0x9000 ┌────────────────────────┐
       │                        │
       │    (unused space)      │
       │                        │
       ├────────────────────────┤
       │ insn byte 0            │ ← 0xA000 - insn_size (= RIP)
       │ insn byte 1            │
       │ ...                    │
       │ insn byte N-1          │ ← 0x9FFF
0xA000 └────────────────────────┘ ← page boundary
       │ (next page — code ends │
       │  here, EPT exec fault  │
       │  if fetch crosses)     │
```

For a 3-byte instruction, it is written at `0x9FFD–0x9FFF` and RIP is set to `0x9FFD`. If the CPU attempts to fetch beyond `0x9FFF` (e.g., because it decoded a prefix and needs more bytes), the fetch crosses into page `0xA000` and triggers an EPT execute violation — signaling that the instruction encoding was incomplete.

### Register Initialization (Canary Values)

Before each instruction executes, all registers are reset to deterministic "canary" values. This allows VMSifter to detect which registers an instruction modified by comparing post-execution values against the known baseline.

| Register | Canary Value | | Register | Canary Value |
|----------|-------------|---|----------|-------------|
| RIP | Set to instruction address | | R8 | `0x1108` |
| RAX | `0x1101` | | R9 | `0x1109` |
| RBX | `0x1102` | | R10 | `0x110A` |
| RCX | `0x1103` | | R11 | `0x110B` |
| RDX | `0x1104` | | R12 | `0x110C` |
| RSI | `0x1105` | | R13 | `0x110D` |
| RDI | `0x1106` | | R14 | `0x110E` |
| RSP | `0x1107` | | R15 | `0x110F` |
| RBP | `0x1108` | | CR2 | `0x1111` |

The formula is `0x1100 + enum_index`, where the enum order is: RIP(0), RAX(1), RBX(2), RCX(3), RDX(4), RSI(5), RDI(6), RSP(7), RBP(8), R8(9), ..., R15(16), CR2(17). RIP is special-cased: it is set to `0xA000 - insn_size` rather than a canary. Custom initial values can be provided via the `--regs-init-value` flag.

After each instruction executes and VMEXITs, the fork's state is reset to the parent snapshot (`VMI_EVENT_RESPONSE_RESET_FORK_STATE`), undoing any memory or register modifications the instruction caused. The C injector then overwrites registers with the canary values and writes the next instruction to memory before resuming.

### XTF Guest Initialization (CPUID Handshake)

The XTF test harness running inside the guest VM configures the CPU environment before the C injector takes over. Communication between the guest and the injector uses a magic CPUID leaf (`0x13371337`), which triggers a VMEXIT that the C injector intercepts:

| Subleaf | Direction | Purpose |
|---------|-----------|---------|
| 0 | Guest → Injector | Setup complete signal. Injector pauses VM, clears HVM params, initializes register canaries, reads perf counter baseline. |
| 1 | Injector → Guest | Performance counter configuration. Returns 4 `PERFEVTSEL` values in RAX/RBX/RCX/RDX. Guest writes them to MSRs `0x186–0x189`. |
| 2 | Injector → Guest | SSE/AVX enablement flag in RAX. Guest sets CR4 flags (`OSFXSR`, `OSXSAVE`, `OSXMMEXCPT`) and XCR0 (`SSE`, `YMM`). |
| 3 | Injector → Guest | SYSCALL enablement flag in RAX. Guest configures `EFER.SCE`, `MSR_STAR`, `MSR_LSTAR`, `MSR_CSTAR`, `MSR_SYSENTER_*`. |
| 4 | Injector → Guest | FPU emulation flag in RAX. Guest sets `CR0.EM` to enable FPU emulation. |

The guest initialization sequence:
1. Query subleaf 2 → optionally enable SSE/AVX
2. Query subleaf 3 → optionally enable SYSCALL/SYSRET
3. Query subleaf 4 → optionally enable FPU emulation
4. Query subleaf 1 → configure performance counters
5. Call subleaf 0 → signal ready; injector takes over execution from this point

```{mermaid}
sequenceDiagram
    participant G as Guest (XTF)
    participant I as Injector (C)
    G->>I: CPUID leaf 0x13371337, subleaf 2
    I-->>G: SSE/AVX flag → sets CR4, XCR0
    G->>I: CPUID subleaf 3
    I-->>G: SYSCALL flag → sets EFER, MSR_STAR, etc.
    G->>I: CPUID subleaf 4
    I-->>G: FPU emulation flag → sets CR0.EM
    G->>I: CPUID subleaf 1
    I-->>G: PERFEVTSEL values in RAX-RDX → writes MSRs
    G->>I: CPUID subleaf 0
    Note over I: Setup complete — pause VM, clear HVM params, init canaries
```

After subleaf 0, the injector pauses the VM, unsets HVM parameters (Xenstore, IOREQ, console, etc.) to minimize hypervisor interference, and the guest never executes its own code again — all subsequent execution is injected instructions.

## Socket Protocol

The Python worker and C injector communicate over a Unix domain socket (`AF_UNIX`, `SOCK_STREAM`) in a synchronous request-response loop:

```{mermaid}
sequenceDiagram
    participant W as Worker (Python)
    participant I as Injector (C)
    W->>I: send(instruction bytes)
    Note right of I: Inject into VM at 0xA000
    Note right of I: VM executes, VMEXITs
    Note right of I: Collect regs, perf ctrs, exit reason
    I->>W: send(InjectorResultMessage)
    Note left of W: Process result, advance fuzzer
    W->>I: send(next instruction)
    Note over W,I: ...repeat until StopIteration...
```

**Message sizes:**
- Instruction: 1-15 bytes (configurable via `insn_buf_size`)
- Result: 264-byte `InjectorResultMessage` struct

### InjectorResultMessage Structure

| Field | Type | Description |
|-------|------|-------------|
| `reason` | uint64 | VMEXIT reason |
| `qualification` | uint64 | VMEXIT qualification |
| `stack_value` | uint64 | Value read from guest stack |
| `perfct[7]` | uint64[7] | Performance counters (3 fixed + 4 programmable) |
| `regs[18]` | uint64[18] | 17 GP registers + CR2 |
| `gla` | uint64 | Guest linear address |
| `intr_info` | uint32 | Interrupt info field |
| `intr_error` | uint32 | Interrupt error code |
| `vec_info` | uint32 | IDT vectoring info |
| `vec_error` | uint32 | IDT vectoring error |
| `insn_size` | uint32 | Instruction length reported by CPU |
| `insn_info` | uint32 | Instruction info field |

## Result Classification

`FuzzerExecResult` hierarchy based on VMEXIT reason:

- **Interrupted**: External interrupt received — retry same instruction
- **NMI**: Includes interrupt type, page fault error code, CR2, stack value
- **EPT**: EPT violation with R/W/X qualification (execute fault = incomplete instruction)
- **Other**: All remaining VMX exit reasons (76 possible)

The factory method `FuzzerExecResult.factory_from_injector_message()` maps the C struct to the appropriate Python subclass.

## Output Format

`CSVOutput` (`vmsifter/output.py`) writes per-worker CSV files:

- `results_{id}.csv` — valid instructions
- `invalid_instructions_{id}.csv` — invalid opcodes

**Columns:** `insn` (hex-encoded bytes), `length`, `exit-type`, `misc` (cpu_len, insn_info, stack value, page fault EC), `pfct1`-`pfct7` (performance counter deltas), `reg-delta` (register changes from canary values).

## Data Flow

```{mermaid}
flowchart TD
    E["SifterExecutor.run()"] --> SF["Select Fuzzer + Injector"]
    E --> P["Partition search space across PCPUs"]
    P --> |"for each PCPU"| INJ["XenVMInjector: create/reuse parent VM, fork (COW), pin to PCPU"]
    INJ --> C["Spawn C injector (Unix socket)"]
    INJ --> W["Worker (subprocess): send/recv loop"]
    W --> F["fuzzer.gen() ↔ socket ↔ C injector ↔ VM fork"]
    W --> CSV["CSVOutput logs results"]
    E --> CL["Collect WorkerStats, cleanup (destroy forks, return PCPUs)"]
```

## CPU Allocation

1. Query Xen via `xl info` for total CPUs
2. Query `xl vcpu-list Domain-0` for Dom0-allocated CPUs
3. Available = Total - Dom0
4. If SMT disabled in config: filter out odd-numbered CPUs (keep physical cores only)
5. Each VM fork is pinned to its assigned PCPU via `xl vcpu-pin --ignore-global-affinity-masks`
