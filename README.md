# kinject

Kernel-level DLL injector using BYOVD (Bring Your Own Vulnerable Driver). Reads and writes
process memory through physical page-table manipulation, bypassing usermode anti-tamper
implementations.

Tested against Roblox (Hyperion) on Windows 10/11 x64.

## How it works

1. Finds a loaded vulnerable signed kernel driver (RTCore64, GIO, iqvw64e, etc.)
2. Uses the driver's exposed physical-memory r/w IOCTLs to walk page tables
3. Resolves the target process EPROCESS and its DirectoryTableBase (CR3)
4. Writes a small position-independent shellcode stub to the target thread's stack
5. Toggles the NX bit off on that stack page via direct PTE modification
6. Hijacks one thread -- sets RIP to the shellcode, pushes the original RIP for return
7. Shellcode calls `LoadLibraryA(payload_path)`, restores volatile registers, returns
8. NX bit is restored on the page after execution

No DLL is needed on disk before injection -- the payload path is embedded in the shellcode
and resolved at runtime by the target process.

## Build

Requires Visual Studio 2022 (or 2019) with the x64 native tools.

```
"C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
cl /O2 /GS- kinject.c /Fe:kinject.exe /link ntdll.lib advapi32.lib
```

Or from a developer command prompt:

```
cl /O2 /GS- kinject.c /Fe:kinject.exe /link ntdll.lib advapi32.lib
```

## Usage

```
kinject.exe                                    PoC against RobloxPlayerBeta
kinject.exe <path\to\payload.dll>              Inject DLL into Roblox
kinject.exe -n <process.exe> <payload.dll>     Inject by process name
kinject.exe -p <pid> <payload.dll>             Inject by PID
```

Examples:

```
> kinject.exe
> kinject.exe C:\Tools\cheat.dll
> kinject.exe -n notepad.exe C:\Tools\hack.dll
> kinject.exe -p 8240 C:\Tools\payload.dll
```

## Requirements

* Windows 10 or 11, x64
* Administrator privileges
* One of the following loaded (vulnerable) kernel drivers:

| Driver              | Source                           |
|---------------------|----------------------------------|
| RTCore64.sys        | MSI Afterburner                  |
| RTCore32.sys        | MSI Afterburner (32-bit)         |
| GIO.sys             | ASUS GPU Tweak II                |
| GLCKIO2.sys         | ASUS GPU Tweak                   |
| Asusgio2/3.sys      | ASUS GPU Tweak III               |
| iqvw64e.sys         | Intel XTU (Extreme Tuning)       |
| Nal.sys             | Intel XTU                        |
| dbk64.sys           | Cheat Engine                     |
| kprocesshacker.sys  | Process Hacker                   |
| WinRing0.sys        | WinRing0 / various tools         |

Additional drivers are probed automatically from the loaded driver service list.

## Notes

* This tool creates **no registry keys, services, or files on disk** (beyond the executable itself).
* Physical memory writes bypass usermode WriteProcessMemory hooks entirely.
* The shellcode executes in the target's address space with the target's token -- no
  cross-process handle duplication needed.
* The stack page NX toggle is restored ~800ms after injection. During that window the page
  is briefly RWX. If the target thread takes an exception during the window, the page
  fault handler will reload the modified PTE and retry transparently.

## Disclaimer

This tool is provided for educational and research purposes only. Using it to modify
software in violation of a ToS or EULA may be unlawful in your jurisdiction.
