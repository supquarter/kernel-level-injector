// kinject.c - kernel injector for roblox
// uses a vulnerable signed driver to read/write physical memory directly
// then walks page tables to inject shellcode that calls LoadLibraryA
//
// build:
//   cl /O2 /GS- kinject.c /Fe:kinject.exe /link ntdll.lib advapi32.lib

#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <tlhelp32.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// shorthand types so we dont have to type unsigned long long everywhere
typedef LONG               NTSTATUS;
typedef unsigned char      u8;
typedef unsigned short     u16;
typedef unsigned int       u32;
typedef unsigned long long u64;
typedef int                i32;

#define NT_SUCCESS(s)       ((NTSTATUS)(s) >= 0)

// all the known vulnerable driver device names we try to open
// most of these ship with common hardware tools (msi afterburner, asus gpu tweak, etc.)
// if you install then uninstall the app, the driver usually stays behind
static const char *g_vuln_drivers[] = {
    "\\\\.\\RTCore64", "\\\\.\\GIO", "\\\\.\\GLCKIO2", "\\\\.\\Asusgio2",
    "\\\\.\\Asusgio3", "\\\\.\\iqvw64e", "\\\\.\\Nal", "\\\\.\\dbk64",
    "\\\\.\\kprocesshacker", "\\\\.\\WinRing0_1_2_0", "\\\\.\\vrw",
    "\\\\.\\atillk64", "\\\\.\\Phymem", "\\\\.\\MsIo64", "\\\\.\\NTIOLib_X64",
    "\\\\.\\RTCore32", "\\\\.\\AODDriver", "\\\\.\\AODDriver2",
    "\\\\.\\AODDriver4.01", "\\\\.\\AODDriver4.1", "\\\\.\\AODDriver4.2",
    "\\\\.\\AODDriver4.3", "\\\\.\\ALSysIO", "\\\\.\\Amifldrv64",
    "\\\\.\\ASMMAP64", "\\\\.\\cpuz137", "\\\\.\\cpu139", "\\\\.\\CoreTemp",
    "\\\\.\\gdrv", "\\\\.\\PassMark", "\\\\.\\HwOs2_64", "\\\\.\\HwOs2_32",
    "\\\\.\\HDRW", "\\\\.\\RTKIO64", "\\\\.\\rwdrv", "\\\\.\\mimidrv",
    "\\\\.\\piddrv64", "\\\\.\\WinIo", "\\\\.\\WinRing0", "\\\\.\\D2DDrv",
    "\\\\.\\ICETool", "\\\\.\\IOMap", "\\\\.\\LGDCore",
    "\\\\.\\LenovoDiagnosticsDriver", "\\\\.\\ProcHelper", "\\\\.\\PhyMemX64",
    "\\\\.\\EneTechIo", "\\\\.\\EneIo64", "\\\\.\\Bioscore",
    "\\\\.\\KProcessHacker3", "\\\\.\\FlashSys",
    NULL
};

// eprocess offsets change between windows builds, so we keep a lookup table
// lo/hi are the build number range, off_pid/off_links/off_dirbase are the field offsets
typedef struct {
    u32 lo, hi;
    u32 off_pid, off_links, off_dirbase;
} off_t;

static const off_t g_builds[] = {
    { 10240, 10586,  0x2E8, 0x2F0, 0x28 },  // win10 1507-1511
    { 14393, 16299,  0x2E0, 0x2E8, 0x28 },  // win10 1607-1709
    { 17134, 22000,  0x440, 0x448, 0x28 },  // win10 1803 - win11 early
    { 22000, 26100,  0x440, 0x448, 0x28 },  // win11 22h2
    { 26100, 99999,  0x440, 0x448, 0x28 },  // win11 24h2+
    { 0, 0, 0, 0, 0 }
};

// global state - these get filled in during bootstrap and used everywhere
static HANDLE  g_dev     = NULL;   // handle to the vulnerable driver
static u64     g_ntos    = 0;      // ntoskrnl physical base
static u64     g_ntos_va = 0;      // ntoskrnl virtual base
static off_t   g_off     = {0};    // resolved eprocess offsets for this build
static u64     g_cr3     = 0;      // our own cr3, used for kernel va->pa translation

// ntdll function pointer for NtQuerySystemInformation
typedef NTSTATUS (NTAPI *NtQSI_t)(
    u32 SystemInformationClass,
    void *SystemInformation,
    u32 SystemInformationLength,
    u32 *ReturnLength
);

// partial SYSTEM_PROCESS_INFORMATION layout, just the fields we need to find the pid
typedef struct {
    u32    NextEntryOffset;
    u32    NumberOfThreads;
    u64    WorkingSetPrivateSize;
    u32    HardFaultCount;
    u32    NumberOfThreadsHighWatermark;
    u64    CycleTime;
    u64    CreateTime;
    u64    UserTime;
    u64    KernelTime;
    u16    ImageNameLen;
    u16    ImageNameMax;
    wchar_t *ImageNameBuf;
    i32    BasePriority;
    void  *UniqueProcessId;
    void  *InheritedFromUniqueProcessId;
    u32    HandleCount;
    u32    SessionId;
    u64    UniqueProcessKey;
    u64    PeakVirtualSize;
    u64    VirtualSize;
    u32    PageFaultCount;
    u64    PeakWorkingSetSize;
    u64    WorkingSetSize;
    u64    QuotaPeakPagedPoolUsage;
    u64    QuotaPagedPoolUsage;
    u64    QuotaPeakNonPagedPoolUsage;
    u64    QuotaNonPagedPoolUsage;
    u64    PagefileUsage;
    u64    PeakPagefileUsage;
    u64    PrivatePageCount;
} spi_base_t;

// the struct we pass to DeviceIoControl for the driver
// a = physical address, b = buffer ptr, s = size
typedef struct { u64 a, b; u32 s; } ioctl_req_t;

// ---- low level: read physical memory through the driver ----
// tries the RTCore64 ioctl first, falls back to GIO/ASUS style
static BOOL phys_read(u64 pa, void *buf, u32 sz) {
    ioctl_req_t r = { pa, (u64)buf, sz };
    u32 rb = 0;
    if (DeviceIoControl(g_dev, 0x80002048, &r, sizeof(r), &r, sizeof(r), &rb, 0))
        return 1;
    return DeviceIoControl(g_dev, 0xC3502800, &r, sizeof(r), &r, sizeof(r), &rb, 0);
}

// ---- low level: write physical memory through the driver ----
static BOOL phys_write(u64 pa, const void *buf, u32 sz) {
    ioctl_req_t r = { pa, (u64)buf, sz };
    u32 rb = 0;
    if (DeviceIoControl(g_dev, 0x8000204C, &r, sizeof(r), &r, sizeof(r), &rb, 0))
        return 1;
    return DeviceIoControl(g_dev, 0xC3502804, &r, sizeof(r), &r, sizeof(r), &rb, 0);
}

// ---- walk x64 page tables to translate a virtual address to physical ----
// cr3 = directory table base (from eprocess), va = virtual address, pa = out
// handles both 4kb and 2mb/1gb large pages
static int vtop(u64 cr3, u64 va, u64 *pa) {
    u64 off  = va & 0xFFF;
    u64 idx[4] = {
        (va >> 39) & 0x1FF,   // pml4 index
        (va >> 30) & 0x1FF,   // pdpt index
        (va >> 21) & 0x1FF,   // pd index
        (va >> 12) & 0x1FF    // pt index
    };
    u64 tbl = cr3 & ~0xFFFULL;   // pml4 physical address (strip flags)
    for (int lv = 0; lv < 4; lv++) {
        u64 ent = 0;
        if (!phys_read(tbl + idx[lv] * 8, &ent, 8)) return 0;
        if (!(ent & 1)) return 0;   // page not present

        // bit 7 = large page at pdpt (1gb) or pd (2mb) level
        if (lv >= 1 && (ent & 0x80)) {
            u64 m = (lv == 1) ? 0xFFFFFC0000000ULL : 0xFFFFFFFE00000ULL;
            u64 o = (lv == 1) ? 0x3FFFFFFFULL : 0x1FFFFFULL;
            *pa = (ent & m) + (va & o);
            return 1;
        }
        tbl = ent & ~0xFFFULL;   // next table level
    }
    *pa = tbl + off;   // 4kb page
    return 1;
}

// ---- read a virtual address by walking page tables ----
static int vread(u64 cr3, u64 va, void *buf, u32 sz) {
    u8 *dst = (u8*)buf;
    while (sz) {
        u64 pg_off = va & 0xFFF;
        u32  chunk  = (u32)((pg_off + sz > 0x1000) ? (0x1000 - pg_off) : sz);
        u64  pa = 0;
        if (!vtop(cr3, va, &pa)) return 0;
        if (!phys_read(pa, dst, chunk)) return 0;
        va  = (va & ~0xFFFULL) + 0x1000;
        dst += chunk;
        sz  -= chunk;
    }
    return 1;
}

// ---- write a virtual address by walking page tables ----
static int vwrite(u64 cr3, u64 va, const void *buf, u32 sz) {
    const u8 *src = (const u8*)buf;
    while (sz) {
        u64 pg_off = va & 0xFFF;
        u32  chunk  = (u32)((pg_off + sz > 0x1000) ? (0x1000 - pg_off) : sz);
        u64  pa = 0;
        if (!vtop(cr3, va, &pa)) return 0;
        if (!phys_write(pa, src, chunk)) return 0;
        va  = (va & ~0xFFFULL) + 0x1000;
        src += chunk;
        sz  -= chunk;
    }
    return 1;
}

// ---- walk page tables to find the PTE physical address for a given VA ----
// we need this to flip the NX bit on the stack page so we can execute shellcode there
static int vtop_pte(u64 cr3, u64 va, u64 *pte_pa) {
    u64 idx[4] = {
        (va >> 39) & 0x1FF,
        (va >> 30) & 0x1FF,
        (va >> 21) & 0x1FF,
        (va >> 12) & 0x1FF
    };
    u64 tbl = cr3 & ~0xFFFULL;
    for (int lv = 0; lv < 3; lv++) {
        u64 ent_pa = tbl + idx[lv] * 8;
        u64 ent = 0;
        if (!phys_read(ent_pa, &ent, 8)) return 0;
        if (!(ent & 1)) return 0;
        if (lv >= 1 && (ent & 0x80)) {   // large page, the pde/pte IS the entry we just read
            *pte_pa = ent_pa;
            return 1;
        }
        tbl = ent & ~0xFFFULL;
    }
    *pte_pa = tbl + idx[3] * 8;   // 4kb page pte
    return 1;
}

// ---- resolve a kernel export by walking ntoskrnl's PE headers ----
// we use this to find PsInitialSystemProcess so we can walk the eprocess linked list
static u64 kexport(u64 cr3, u64 kva, const char *name) {
    IMAGE_DOS_HEADER       dos;
    IMAGE_NT_HEADERS64     nth;
    IMAGE_EXPORT_DIRECTORY exp;

    if (!vread(cr3, kva, &dos, sizeof(dos))) return 0;
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) return 0;

    if (!vread(cr3, kva + dos.e_lfanew, &nth, sizeof(nth))) return 0;
    if (nth.Signature != IMAGE_NT_SIGNATURE) return 0;

    u64 edir = kva + nth.OptionalHeader
                   .DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!vread(cr3, edir, &exp, sizeof(exp))) return 0;

    u64 names = kva + exp.AddressOfNames;
    u64 funcs = kva + exp.AddressOfFunctions;
    u64 ords  = kva + exp.AddressOfNameOrdinals;

    for (u32 i = 0; i < exp.NumberOfNames; i++) {
        u32 rva = 0; u16 ord = 0;
        char sym[256] = {0};
        if (!vread(cr3, names + i*4, &rva, 4)) continue;
        if (!vread(cr3, ords  + i*2, &ord, 2)) continue;
        if (!vread(cr3, kva + rva, sym, sizeof(sym)-1)) continue;
        if (strcmp(sym, name)) continue;
        u32 frva = 0;
        if (!vread(cr3, funcs + ord*4, &frva, 4)) continue;
        return kva + frva;
    }
    return 0;
}

// ---- get the windows build number so we know which eprocess offsets to use ----
static u32 winbuild(void) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) return 0;
    typedef LONG (WINAPI *RGV_t)(PRTL_OSVERSIONINFOW);
    RGV_t f = (RGV_t)GetProcAddress(ntdll, "RtlGetVersion");
    if (!f) return 0;
    RTL_OSVERSIONINFOW v = { sizeof(v) };
    if (f(&v)) return 0;
    return v.dwBuildNumber;
}

// ---- get the directory table base (cr3) for any process by pid ----
// uses SystemExtendedProcessInformation from ntdll, which returns the cr3 per-process
// the cr3 offset inside the struct varies across builds so we scan for it heuristically
static u64 get_dirbase(u32 pid) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    NtQSI_t qsi = (NtQSI_t)GetProcAddress(ntdll, "NtQuerySystemInformation");
    if (!qsi) return 0;

    // try a few known system information class ids for extended process info
    u32 classes[] = { 0x39, 0x3D, 0x3E, 0 };
    u8  *buf = 0;
    u32  need = 0;

    for (int ci = 0; classes[ci]; ci++) {
        need = 0;
        if (!NT_SUCCESS(qsi(classes[ci], 0, 0, &need)) || !need) continue;
        buf = VirtualAlloc(0, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf) continue;
        if (NT_SUCCESS(qsi(classes[ci], buf, need, &need))) break;
        VirtualFree(buf, 0, MEM_RELEASE);
        buf = 0;
    }
    if (!buf) return 0;

    u64 cr3 = 0;
    u8 *cur = buf;
    for (;;) {
        u32 next = *(u32*)(cur + 0);
        // pid is at offset 0x50 in the standard process info header
        void *epid = *(void**)(cur + 0x50);
        if ((u32)(u64)epid == pid) {
            // directory table base is always page-aligned and in a sane physical range
            // scan forward from the pid until we hit one that looks like a valid cr3
            for (u32 off = 0x50; off + 8 <= 0x200; off += 8) {
                u64 v = *(u64*)(cur + off);
                if (v && (v & 0xFFF) == 0 && v >= 0x1000 && v < 0x10000000000ULL) {
                    cr3 = v;
                    break;
                }
            }
            break;
        }
        if (!next) break;
        cur += next;
    }
    VirtualFree(buf, 0, MEM_RELEASE);
    return cr3;
}

// ---- probe a single driver device to see if it gives us physical r/w ----
// opens the device, sends a test read ioctl, closes it
static BOOL driver_probe(const char *name) {
    HANDLE h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE,
                           0, 0, OPEN_EXISTING, 0, 0);
    if (h == INVALID_HANDLE_VALUE) return 0;

    // physical address 0x1000 is always mapped on x86, try reading 8 bytes from it
    u64 v = 0;
    ioctl_req_t r = { 0x1000, (u64)&v, 8 };
    u32 rb = 0;
    BOOL ok = DeviceIoControl(h, 0x80002048, &r, sizeof(r), &r, sizeof(r), &rb, 0)
           || DeviceIoControl(h, 0xC3502800, &r, sizeof(r), &r, sizeof(r), &rb, 0);

    CloseHandle(h);
    return ok;
}

static char g_drv_name[MAX_PATH] = {0};

// ---- find and open a vulnerable driver ----
// first checks our known list, then falls back to enumerating all kernel services
static BOOL driver_acquire(void) {
    int found = 0;

    // try all the known device names we hardcoded
    for (int i = 0; g_vuln_drivers[i]; i++) {
        if (driver_probe(g_vuln_drivers[i])) {
            strncpy(g_drv_name, g_vuln_drivers[i], MAX_PATH - 1);
            printf(" [+] driver: %s\n", g_drv_name);
            found = 1;
            break;
        }
    }

    // if none of the known names worked, walk the service manager looking for drivers
    if (!found) {
        SC_HANDLE scm = OpenSCManagerA(0, 0, SC_MANAGER_ENUMERATE_SERVICE);
        if (scm) {
            u32 need = 0, cnt = 0;
            EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
                SERVICE_DRIVER, SERVICE_STATE_ALL,
                0, 0, &need, &cnt, 0, 0);
            LPENUM_SERVICE_STATUS_PROCESSA svc = malloc(need);
            if (svc && EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO,
                SERVICE_DRIVER, SERVICE_STATE_ALL,
                (LPBYTE)svc, need, &need, &cnt, 0, 0)) {
                for (u32 i = 0; i < cnt && !found; i++) {
                    char dev[MAX_PATH];
                    _snprintf(dev, MAX_PATH, "\\\\.\\%s", svc[i].lpServiceName);
                    if (driver_probe(dev)) {
                        strncpy(g_drv_name, dev, MAX_PATH - 1);
                        printf(" [+] driver (enum): %s\n", svc[i].lpServiceName);
                        found = 1;
                    }
                }
            }
            free(svc);
            CloseServiceHandle(scm);
        }
    }

    if (!found) {
        printf(" [-] no vulnerable driver found\n");
        printf(" [*] install MSI Afterburner, Intel XTU, or ASUS GPU Tweak II\n");
        return 0;
    }

    // open the working driver with full r/w for actual use
    g_dev = CreateFileA(g_drv_name,
        GENERIC_READ | GENERIC_WRITE, 0, 0,
        OPEN_EXISTING, 0, 0);

    if (g_dev == INVALID_HANDLE_VALUE) {
        printf(" [-] failed to open %s\n", g_drv_name);
        return 0;
    }

    return 1;
}

// ---- bootstrap: resolve kernel base, get a cr3, figure out offsets ----
// this runs once at startup and fills in all the globals
static int bootstrap(void) {
    // get ntoskrnl base address from the system module list
    {
        NtQSI_t qsi = (NtQSI_t)GetProcAddress(
            GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
        if (!qsi) { printf(" [-] NtQuerySystemInformation missing\n"); return 0; }

        u32 need = 0;
        qsi(0x0B, 0, 0, &need);   // SystemModuleInformation
        void *buf = VirtualAlloc(0, need, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!buf || !NT_SUCCESS(qsi(0x0B, buf, need, 0))) {
            VirtualFree(buf, 0, MEM_RELEASE);
            printf(" [-] SystemModuleInformation failed\n");
            return 0;
        }
        // the structure is: u32 count, u32 pad, then module entries
        // each entry: u32 unknown1, u32 unknown2, PVOID base, ...
        // so first module base is at buf + 8 + 8 = buf + 16
        g_ntos_va = *(u64*)((u8*)buf + 16);
        VirtualFree(buf, 0, MEM_RELEASE);
    }

    if (!g_ntos_va) {
        printf(" [-] could not resolve ntoskrnl base\n");
        return 0;
    }
    printf(" [+] ntoskrnl: 0x%llX\n", g_ntos_va);

    // get our own process cr3 - we need this to translate kernel virtual addresses
    // kernel page tables are shared, so any process cr3 works for kernel va->pa
    g_cr3 = get_dirbase(GetCurrentProcessId());
    if (!g_cr3) {
        printf(" [-] could not get our own CR3\n");
        return 0;
    }

    // translate ntoskrnl from virtual to physical so kexport() can walk its PE
    if (!vtop(g_cr3, g_ntos_va, &g_ntos)) {
        printf(" [-] ntoskrnl va->pa translation failed\n");
        return 0;
    }

    // figure out which eprocess offset table to use based on windows build
    {
        u32 b = winbuild();
        printf(" [*] windows build: %u\n", b);
        for (int i = 0; g_builds[i].hi; i++) {
            if (b >= g_builds[i].lo && b <= g_builds[i].hi) {
                g_off = g_builds[i];
                break;
            }
        }
        if (!g_off.off_pid) {
            printf(" [!] unknown build, using win10 1803+ defaults\n");
            g_off.off_pid     = 0x440;
            g_off.off_links   = 0x448;
            g_off.off_dirbase = 0x28;
        }
    }

    return 1;
}

// ---- walk the eprocess linked list from PsInitialSystemProcess to find our target ----
// returns the eprocess address and fills in the target's cr3
static u64 find_eprocess(u32 pid, u64 *cr3_out) {
    u64 psinit = kexport(g_cr3, g_ntos_va, "PsInitialSystemProcess");
    if (!psinit) {
        printf(" [-] PsInitialSystemProcess not found\n");
        return 0;
    }

    u64 cur = 0;
    if (!vread(g_cr3, psinit, &cur, 8)) return 0;

    u64 start = cur;
    for (int n = 0; n < 32768; n++) {
        u32 p = 0;
        u64 db = 0;

        if (!vread(g_cr3, cur + g_off.off_pid,     &p,  4)) break;
        if (!vread(g_cr3, cur + g_off.off_dirbase, &db, 8)) break;

        if (p == pid) {
            *cr3_out = db;
            return cur;
        }

        // follow flink to next eprocess
        u64 links = 0;
        if (!vread(g_cr3, cur + g_off.off_links, &links, 8)) break;
        cur = links - g_off.off_links;
        if (cur == start) break;   // full loop, target not found
    }

    return 0;
}

// ---- build the x64 shellcode that calls LoadLibraryA and returns cleanly ----
// layout: [machine code 0x30 bytes] [LoadLibraryA ptr 8 bytes] [dll path string]
// the code saves volatile regs, calls LoadLibraryA, restores regs, rets
// rip-relative addressing is used so it works anywhere we drop it
static u32 build_sc(u8 *out, u32  max, u64 ll, const char *dll) {
    u32 plen = (u32)strlen(dll) + 1;
    u32 csz  = 0x30;                     // code section size
    u32 tsz  = csz + 8 + plen;           // total shellcode size
    if (tsz > max) return 0;

    // rip-relative offsets from the lea/mov instructions to the data section
    i32 doff = (i32)(csz + 8  - (0x0F + 7));   // lea rcx, [rip + X] -> dll string
    i32 loff = (i32)(csz      - (0x16 + 7));   // mov rax, [rip + X] -> LoadLibraryA ptr

    u8 code[] = {
        0x50,                           // push rax
        0x51,                           // push rcx
        0x52,                           // push rdx
        0x41,0x50,                      // push r8
        0x41,0x51,                      // push r9
        0x41,0x52,                      // push r10
        0x41,0x53,                      // push r11
        0x48,0x83,0xEC,0x28,           // sub  rsp, 0x28
        0x48,0x8D,0x0D,                // lea  rcx, [rip + doff]
            (u8)doff,(u8)(doff>>8),(u8)(doff>>16),(u8)(doff>>24),
        0x48,0x8B,0x05,                // mov  rax, [rip + loff]
            (u8)loff,(u8)(loff>>8),(u8)(loff>>16),(u8)(loff>>24),
        0xFF,0xD0,                      // call rax
        0x48,0x83,0xC4,0x28,           // add  rsp, 0x28
        0x41,0x5B,                      // pop  r11
        0x41,0x5A,                      // pop  r10
        0x41,0x59,                      // pop  r9
        0x41,0x58,                      // pop  r8
        0x5A,                           // pop  rdx
        0x59,                           // pop  rcx
        0x58,                           // pop  rax
        0xC3                            // ret
    };

    memcpy(out, code, sizeof(code));
    memcpy(out + 0x30, &ll,   8);       // embed loadlibrary address
    memcpy(out + 0x38, dll, plen);      // embed dll path string
    return tsz;
}

// ---- grab any thread from the target process that we can suspend and hijack ----
static HANDLE grab_thread(u32 pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    THREADENTRY32 te = { sizeof(te) };
    HANDLE h = 0;
    if (Thread32First(snap, &te)) do {
        if (te.th32OwnerProcessID == pid) {
            h = OpenThread(
                THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT |
                THREAD_SET_CONTEXT, 0, te.th32ThreadID);
            if (h) break;
        }
    } while (Thread32Next(snap, &te));

    CloseHandle(snap);
    return h;
}

// ---- the main injection routine ----
// 1. find target eprocess and get its cr3
// 2. grab a thread and suspend it
// 3. write shellcode to the thread's stack page
// 4. flip nx bit off on that page so we can execute there
// 5. push original rip onto the stack, set rip to our shellcode
// 6. resume the thread -> shellcode runs, calls LoadLibraryA, returns normally
// 7. restore the nx bit after the shellcode had time to run
static int inject(u32 pid, const char *dll) {
    u64 cr3 = 0;
    u64 ep  = find_eprocess(pid, &cr3);
    if (!ep || !cr3) {
        printf(" [-] could not find target eprocess\n");
        return 0;
    }
    printf(" [+] target cr3: 0x%llX\n", cr3);

    // resolve LoadLibraryA address in our own process
    // kernel32 is at the same base in target process since session-wide aslr
    u64 ll = (u64)GetProcAddress(GetModuleHandleA("kernel32.dll"),
                                 "LoadLibraryA");
    if (!ll) {
        printf(" [-] LoadLibraryA not found\n");
        return 0;
    }

    HANDLE th = grab_thread(pid);
    if (!th) {
        printf(" [-] no target thread to hijack\n");
        return 0;
    }

    if (SuspendThread(th) == (u32)-1) {
        printf(" [-] suspend failed\n");
        CloseHandle(th);
        return 0;
    }

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(th, &ctx)) {
        ResumeThread(th);
        CloseHandle(th);
        printf(" [-] GetThreadContext failed\n");
        return 0;
    }

    // use the bottom of the thread's stack page for shellcode
    // the thread is suspended so its active stack data is near rsp,
    // writing at page start is safe
    u64 stk_pg = ctx.Rsp & ~0xFFFULL;
    u64 sc_va  = stk_pg;

    // find the pte for the stack page so we can toggle nx
    u64 pte = 0;
    if (!vtop_pte(cr3, stk_pg, &pte)) {
        printf(" [-] vtop_pte failed\n");
        goto fail;
    }

    u64 orig_pte = 0;
    if (!phys_read(pte, &orig_pte, 8)) {
        printf(" [-] read PTE failed\n");
        goto fail;
    }

    // make sure the page exists and is writable before we write to it
    if (!(orig_pte & 1) || !(orig_pte & 2)) {
        printf(" [-] stack page not mapped (PTE=0x%llX)\n", orig_pte);
        goto fail;
    }

    // clear the no-execute bit (bit 63 in the pte)
    // this makes the stack page executable so our shellcode can run there
    u64 new_pte = orig_pte & ~(1ULL << 63);
    if (!phys_write(pte, &new_pte, 8)) {
        printf(" [-] PTE write failed\n");
        goto fail;
    }

    // build the shellcode with the dll path baked in
    u8 sc[512] = {0};
    u32 scsz = build_sc(sc, sizeof(sc), ll, dll);
    if (!scsz) { printf(" [-] shellcode too big\n"); goto fail_pte; }

    // write shellcode into the target process via physical memory
    if (!vwrite(cr3, sc_va, sc, scsz)) {
        printf(" [-] shellcode write failed\n");
        goto fail_pte;
    }

    // double check the shellcode landed correctly
    {
        u8 vfy[64];
        if (!vread(cr3, sc_va, vfy, 64) || memcmp(vfy, sc, 64)) {
            printf(" [-] shellcode verify failed\n");
            goto fail_pte;
        }
    }

    // push the original rip onto the thread's stack
    // when the shellcode hits "ret" it'll pop this and jump back where it was
    u64 orig_rip = ctx.Rip;
    ctx.Rsp -= 8;
    if (!vwrite(cr3, ctx.Rsp, &orig_rip, 8)) {
        printf(" [-] stack write failed\n");
        goto fail_pte;
    }

    // redirect the thread to our shellcode
    ctx.Rip = sc_va;

    if (!SetThreadContext(th, &ctx)) {
        printf(" [-] SetThreadContext failed\n");
        ctx.Rsp += 8;
        goto fail_pte;
    }

    printf(" [*] hijack: RIP 0x%llX -> 0x%llX\n", orig_rip, sc_va);

    // let it rip
    ResumeThread(th);

    // give the shellcode time to run, then put the nx bit back
    Sleep(800);
    phys_write(pte, &orig_pte, 8);

    CloseHandle(th);
    printf(" [+] injection complete\n");
    return 1;

fail_pte:
    phys_write(pte, &orig_pte, 8);
fail:
    ResumeThread(th);
    CloseHandle(th);
    return 0;
}

// ---- find a process by name, returns pid or 0 ----
static u32 find_pid(const char *name) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32 pe = { sizeof(pe) };
    u32 pid = 0;
    if (Process32First(snap, &pe)) do {
        if (!_stricmp(pe.szExeFile, name)) { pid = pe.th32ProcessID; break; }
    } while (Process32Next(snap, &pe));

    CloseHandle(snap);
    return pid;
}

static void usage(const char *me) {
    printf(
        "\n"
        "  kinject  --  kernel-level injector for roblox\n\n"
        "  usage:\n"
        "    %s                                    inject Module.dll into roblox\n"
        "    %s <dll>                              inject a specific dll\n"
        "    %s -n <name> <dll>                    inject by process name\n"
        "    %s -p <pid>  <dll>                    inject by pid\n\n"
        "  default payload: Module.dll (rename your dll to Module.dll)\n"
        "  run as admin, needs a vulnerable driver loaded\n\n",
        me, me, me, me);
}

int main(int argc, char **argv) {
    const char *target = "RobloxPlayerBeta.exe";
    u32         pid    = 0;
    const char *dll    = 0;
    char        def[MAX_PATH] = {0};

    if (argc >= 2) {
        if (!strcmp(argv[1], "-h") || !strcmp(argv[1], "--help")) {
            usage(argv[0]); return 0;
        }
        if (!strcmp(argv[1], "-n")) {
            if (argc < 4) { usage(argv[0]); return 1; }
            target = argv[2];
            dll    = argv[3];
        } else if (!strcmp(argv[1], "-p")) {
            if (argc < 4) { usage(argv[0]); return 1; }
            pid = (u32)atoi(argv[2]);
            dll = argv[3];
        } else {
            dll = argv[1];
        }
    }

    if (!dll) {
        // no dll given, we look for Module.dll next to the exe
        GetFullPathNameA("Module.dll", MAX_PATH, def, 0);
        dll = def;
        printf(" [*] payload: %s\n", dll);
    }

    // step 1: get ntos base, resolve our own cr3, figure out offsets
    printf("\n  -- kinject --\n\n");
    if (!bootstrap()) return 1;

    // step 2: find roblox
    if (!pid) {
        pid = find_pid(target);
        if (!pid) { printf(" [-] %s is not running\n", target); return 1; }
    }
    printf(" [+] target: %s  (pid %u)\n", target, pid);
    printf(" [*] payload: %s\n", dll);

    // step 3: find a vulnerable driver to use
    printf(" [*] searching for vulnerable driver...\n");
    if (!driver_acquire()) return 1;

    // step 4: inject
    if (!inject(pid, dll)) {
        printf(" [-] injection failed\n");
        return 1;
    }

    printf("\n [+] done.\n");
    return 0;
}
