# ArgusMonitor.sys — BYOVD Research

**by KyFu** | Submitted to [LOLDrivers](https://github.com/magicsword-io/LOLDrivers)

---

## What is this?

ArgusMonitor is a hardware temperature monitoring and fan control application made by **Argotronic UG** out of Germany. Like a lot of these monitoring tools, it ships a kernel driver — `ArgusMonitor.sys` — to get low-level access to hardware sensors. The problem is that this driver hands out that access to *anyone* who asks.

No authentication. No process checks. No DACL on the device. You just open it and you're in ring-0.

This repo documents the attack surface and includes a PoC (`ampoc.py`) that proves it.

---

## Why does this matter?

This driver is:
- **WHQL attestation signed** with an **active Microsoft EV certificate** from Argotronic UG
- Loadable on **any x64 Windows** system without needing Argus Monitor installed
- **Not in the HVCI blocklist**
- **Not in LOLDrivers** (until now)

That means an attacker can drop this on any machine, load it with `sc.exe`, and immediately have physical memory read/write, arbitrary port I/O, PCI config writes, and a path to disable NX system-wide. No driver signing bypass needed. No UEFI tricks. The cert is valid.

---

## The Handshake

The driver does have a handshake mechanism, which sounds like it should be a gate. It isn't.

You send a `0x200`-byte buffer to `IOCTL_HANDSHAKE (0x9c402b74)`. The driver XORs your input against a keypad of your own choosing, then validates a `uint16` checksum over the result. Since *you* supply the keypad, sending all zeros is equivalent to no XOR at all — and a buffer of zeros has a valid checksum of zero. The handshake passes unconditionally.

Once you're past it, all 47 IOCTLs are unlocked.

---

## What the Driver Can Do

### Physical Memory (via `MmMapIoSpace`)

The driver maintains 32 mapping slots, each supporting up to 128 KB. You pick a physical address, it maps it into kernel virtual address space and gives you a handle back. From there you can read and write DWORDs or individual bytes through that mapping.

There's also a **single-shot read** primitive (`IOCTL_PHYSMEM_SINGLE, 0x9c402994`). The slot-based path has a guard that's supposed to restrict low physical addresses — the single-shot path takes a `busNum` parameter that, when set to `0xFF`, bypasses that check entirely. No address is off limits.

This is enough for a full KASLR bypass: scan physical memory for `MZ` headers, confirm the PE signature, and you've found the kernel base.

### Port I/O

Unrestricted `IN`/`OUT` to any port in `0x0000–0xFFFF`. The PoC demos this by reading the RTC (ports `0x70`/`0x71`). In practice this means full CMOS access, PCI config space via `0xCF8`/`0xCFC`, SMBus via `0xB00`+, and anything else mapped to I/O ports on the system.

### PCI Configuration Space

Two dedicated IOCTLs wrap `HalGetBusDataByOffset` and `HalSetBusDataByOffset` directly. Read any PCI config register, write any PCI config register. No bus/device/function restriction. This includes BAR remapping — you can relocate a device's MMIO region to wherever you want.

### MSR Read/Write

The driver reads and writes MSRs with a whitelist. `IA32_LSTAR` (`0xC0000082`) is blocked on reads — so you can't directly pull the kernel's syscall entry point that way. But `IA32_MISC_ENABLE` (`0x1A0`) is **not blocked on writes**. Clearing bit 34 of that MSR disables the XD/NX feature system-wide. Every page in memory becomes executable.

Combined with arbitrary physical memory write, you don't need the syscall entry point anyway.

### I2C / SMBus

The driver exposes I2C and SMBus access via MMIO bit-banging. Useful for reading SPD data off DIMMs, poking at embedded controllers, or accessing sensors that aren't on the PCI bus.

### No Device Security

`IoCreateDevice` is called with no security descriptor. The device object has no DACL, which means the default object ACL applies — readable and writable by any user. `IRP_MJ_CREATE` returns `STATUS_SUCCESS` with zero caller validation. Any process, any integrity level, can open the device.

---

## PoC Output

```
========================================================
  [+] HANDSHAKE     zero keypad accepted, all IOCTLs unlocked

  [PASS] Port I/O             RTC 2026-07-22 10:09:09
  [PASS] PCI config           13 devices via HAL; first 8086:4660 @ slot 0
  [PASS] PCI via PIO          13 devices via 0xCF8/0xCFC (matches HAL)
  [PASS] MSR read             MPERF=0x1E458D5E2C80
  [PASS] MSR block            IA32_LSTAR blocked by whitelist
  [PASS] PhysMem map+read     0xFEE00000 -> KVA 0xFFFFF3049EFD4000; APIC_ID=0xFFFFFFFF APIC_VER=0xFFFFFFFF
  [PASS] PhysMem WR DW        idempotent writeback confirmed
  [PASS] PhysMem WR B         read 0xFF, writeback confirmed
  [PASS] Single-shot read     0xFFFF0=0x00000000 0xFFFE0=0x00000000 (address restriction bypassed)
  [PASS] PE scan              kernel PE at phys 0x00743000 (MZ+PE)

  --------------------------------------------------------
  RESULTS: 10 PASS, 0 WARN, 0 FAIL, 10 total
  --------------------------------------------------------
  SHA256    : df9b2892498c68805fdc0fabb369f8bcf011e784898cb32fdc5d85f6123f1126
  Signed    : Argotronic UG (EV certificate, active)
  Auth      : XOR keypad (user-chosen) + uint16 checksum
  LOLDrivers: YES  |  HVCI blocked: NO  |  CVE: NONE
  PoC by NotKyFu
========================================================
```

---

## Running the PoC

Requires administrator privileges and Python 3. Place `ArgusMonitor.sys` in the same directory as `ampoc.py`.

```bash
python ampoc.py
```

The script loads the driver via `sc.exe`, performs the handshake, runs each test, unloads the driver, and prints the summary above.

---

## Hashes

| File | SHA256 |
|------|--------|
| `ArgusMonitor.sys` | `df9b2892498c68805fdc0fabb369f8bcf011e784898cb32fdc5d85f6123f1126` |

---

## Mitigation

Add the SHA256 hash to your WDAC Supplemental Policy as a `<Deny>` rule, or block the Argotronic UG EV signer entirely. Microsoft's [Vulnerable Driver Blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/windows-defender-application-control/design/microsoft-recommended-driver-block-rules) update is pending.

Use at own discretion

HVCI does **not** block this driver in its current state.

---
