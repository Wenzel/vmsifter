# Xen Patches

VMSifter requires a custom Xen build with patches that enable high-speed, high-precision CPU instruction fuzzing within forked VMs. Standard Xen VM forking (`xc_memshr_fork()`) provides basic copy-on-write cloning, but lacks the performance, determinism, and observability needed for instruction-level fuzzing.

There are **8 patches** targeting three components: Xen hypervisor (5), LibVMI (1), and XTF (1), plus a shared domctl extension.

## Performance Counter Access

### Configurable MSR reads (xen-domctl)

Extends `XEN_DOMCTL_get_vcpu_msrs` to read **arbitrary guest MSRs**, not just the hardcoded set used for migration. Adds the `xc_vcpu_get_msrs()` API and `vpmu_get_msr()` with Intel implementation (AMD is a stub).

The C injector calls this after every instruction execution to read 7 performance counters (3 fixed IA32_FIXED_CTR0-2 + 4 programmable IA32_PMC0-3).

### Performance counter freeze bits (xen-allow-guest-setting-perfmon-freeze)

Extends `IA32_DEBUGCTL` MSR write validation to allow `FREEZE_ON_PMI` (bit 12) and `FREEZE_WHILE_SMM` (bit 14). Standard Xen only permits LBR and BTF bits.

The XTF parent VM sets `IA32_DEBUGCTL = 0x5000` to prevent counter noise from SMM and PMI during instruction execution. Without this patch, Xen rejects the write.

## Complete VMEXIT Reporting

### Extended VMEXIT info in Xen (xen-monitor-report-extra-vmexit-information)

Creates `struct vmexit_info` and extracts 9 additional VMCS fields on every VMEXIT:

| Field | VMCS Source |
|-------|-------------|
| Guest Linear Address | `GUEST_LINEAR_ADDRESS` |
| Interruption Info | `VM_EXIT_INTR_INFO` |
| Interruption Error Code | `VM_EXIT_INTR_ERROR_CODE` |
| IDT Vectoring Info | `IDT_VECTORING_INFO` |
| IDT Vectoring Error Code | `IDT_VECTORING_ERROR_CODE` |
| Instruction Length | `VM_EXIT_INSTRUCTION_LEN` |
| Instruction Info | `VMX_INSTRUCTION_INFO` |
| Exit Qualification | `EXIT_QUALIFICATION` |
| Exit Reason | (implicit) |

Fields are poisoned to `0xbeef` after reading as a debug aid. The monitor subsystem is updated to pass the full `vmexit_info` struct instead of just reason + qualification.

### Extended VMEXIT info in LibVMI (libvmi-vmexit-instruction-infos)

Extends LibVMI's `vmexit_event_t` to expose 7 of the new fields (GLA, interruption info/error, IDT vectoring info/error, instruction length, instruction info) to userspace, where the C injector consumes them.

## Deterministic CPU State

### FPU pre-load (xen-vmx-Load-FPU-state-before-entering)

Forces FPU state to be loaded before VM entry by calling `vmx_fpu_dirty_intercept()` in `vmx_vmenter_helper()`. Standard Xen uses lazy FPU loading (deferred until the first FPU instruction), which introduces non-deterministic state across instruction executions.

### Full exception capture (xen-Capture-all-exceptions-as-vmexits)

Sets the VMX exception bitmap to `~0` (all 32 exception types) for fork domains, so every exception causes a VMEXIT. Without this, some exceptions would be delivered directly to the guest, hiding instruction behavior from the fuzzer.

## Fork Performance

### Skip unnecessary fork setup (xen-Skip-setting-copying-magic-pages)

Disables three functions during fork creation via `#if 0` blocks:

- `domain_creation_finished()` — skips APIC MMIO page setup
- `copy_tsc()` — skips TSC configuration copying from parent
- `copy_special_pages()` — skips APIC/IOAPIC page copying

These are unnecessary overhead for ephemeral forks that don't use APIC and shouldn't inherit TSC state. Removing them reduces fork creation latency.

### VPID pinning (xen-VPID-pinning)

Pins VPID (Virtual Processor ID) to the domain ID for fork domains instead of using Xen's dynamic ASID allocation. Skips `hvm_asid_flush_vcpu()` for forks. This is safe because forks are pinned to specific PCPUs and short-lived, so dynamic TLB management is pure overhead.

## Noise Reduction

### Silence HVM save/restore logging (xen-Silence-too-verbose-debug-log)

Comments out 3 `XENLOG_G_INFO` printk calls in HVM save/restore. Fork creation triggers these operations thousands of times per second, flooding hypervisor logs.

## Guest VM Setup (XTF)

### VMSifter test VM (xtf-VMSifter-test-execution-VM)

Creates a new XTF test at `tests/vmsifter/` that serves as the parent VM for forking. The guest boot code uses a magic CPUID leaf (`0x13371337`) with 4 subleaves to request feature configuration from the hypervisor:

| Subleaf | Purpose |
|---------|---------|
| 1 | Configure performance counter MSRs (0x186-0x189) |
| 2 | Enable SSE/AVX (CR4 flags + XCR0 state) |
| 3 | Enable SYSCALL/SYSRET (EFER, MSR_STAR, MSR_LSTAR, MSR_CSTAR, SYSENTER MSRs) |
| 4 | Enable FPU emulation (CR0.EM) |

The injector's CPUID event handler (`cpuid_cb` in `main.c`) intercepts these requests and configures the VM accordingly. After setup, the parent VM is ready to be forked.

## Applying the Patches

```bash
# Xen hypervisor
cd xen/
find ../patches/ -type f -name '*-xen-*' -exec git apply {} \;

# LibVMI
cd libvmi/
find ../patches/ -type f -name '*-libvmi-*' -exec git apply {} \;

# XTF
cd xtf/
find ../patches/ -type f -name '*-xtf-*' -exec git apply {} \;
```
